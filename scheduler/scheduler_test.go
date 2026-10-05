package scheduler

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegisterRejectsInvalidSpec(t *testing.T) {
	s := New(discardLogger())

	err := s.Register("bad-job", "not a cron spec", func(context.Context) error {
		return nil
	})

	if err == nil {
		t.Fatal("expected invalid cron spec to return an error")
	}
}

func TestWrappedJobRunsRegisteredFunction(t *testing.T) {
	s := New(discardLogger())
	var called atomic.Bool

	job := s.wrapJob("test-job", func(ctx context.Context) error {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 {
			t.Fatal("expected job context to have a future deadline")
		}
		called.Store(true)
		return nil
	})
	job()

	if !called.Load() {
		t.Fatal("expected wrapped job to call registered function")
	}
}

// The first run blocks until cleanup, so every later tick overlaps it no matter where in the
// wall-clock second the test starts. A fixed sleep window let a legitimate run start after it.
func TestSchedulerSkipsOverlappingRuns(t *testing.T) {
	skips := make(chan struct{}, 1)
	s := New(slog.New(skipSignalHandler{skips: skips}))
	runStarts := make(chan struct{}, 1)
	releaseRuns := make(chan struct{})
	var runs atomic.Int32

	err := s.Register("slow-job", "@every 1s", func(context.Context) error {
		runs.Add(1)
		notify(runStarts)
		<-releaseRuns
		return nil
	})
	if err != nil {
		t.Fatalf("register slow job: %v", err)
	}

	s.Start()
	t.Cleanup(func() {
		close(releaseRuns)
		stopScheduler(t, s)
	})

	// Wait for the first run, then for a tick that fires while it still holds the overlap guard
	select {
	case <-runStarts:
	case <-time.After(signalTimeout):
		t.Fatal("timed out waiting for the first run to start")
	}
	select {
	case <-skips:
	case <-runStarts:
		t.Fatalf("expected overlapping run to be skipped, got %d runs", runs.Load())
	case <-time.After(signalTimeout):
		t.Fatal("timed out waiting for the overlapping run to be skipped")
	}

	if got := runs.Load(); got != 1 {
		t.Fatalf("expected overlapping run to be skipped, got %d runs", got)
	}
}

// A panicking run must not leave the overlap guard locked, or every later tick is skipped.
func TestSchedulerRunsJobAgainAfterPanic(t *testing.T) {
	s := New(discardLogger())
	var runs atomic.Int32
	secondRun := make(chan struct{}, 1)

	err := s.Register("panicking-job", "@every 1s", func(context.Context) error {
		if runs.Add(1) == 1 {
			panic("first run fails")
		}
		notify(secondRun)
		return nil
	})
	if err != nil {
		t.Fatalf("register panicking job: %v", err)
	}

	s.Start()
	defer stopScheduler(t, s)

	select {
	case <-secondRun:
	case <-time.After(signalTimeout):
		t.Fatalf("expected job to run again after a panic, got %d runs", runs.Load())
	}
}

// signalTimeout bounds every wait on a job signal; generous so slow CI does not flake.
const signalTimeout = 10 * time.Second

// cronSkipMessage is what cron.SkipIfStillRunning logs when the previous run still holds the guard.
const cronSkipMessage = "skip"

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// notify signals ch without blocking when a signal is already pending.
func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func stopScheduler(t *testing.T, s *Scheduler) {
	t.Helper()
	stopCtx, cancel := context.WithTimeout(context.Background(), signalTimeout)
	defer cancel()
	if err := s.Stop(stopCtx); err != nil {
		t.Errorf("stop scheduler: %v", err)
	}
}

// skipSignalHandler is a slog handler that signals each run the overlap guard skips.
type skipSignalHandler struct {
	skips chan<- struct{}
}

func (h skipSignalHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h skipSignalHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Message == cronSkipMessage {
		notify(h.skips)
	}
	return nil
}

func (h skipSignalHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h skipSignalHandler) WithGroup(string) slog.Handler { return h }
