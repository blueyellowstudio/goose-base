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

func TestSchedulerSkipsOverlappingRuns(t *testing.T) {
	s := New(discardLogger())
	var runs atomic.Int32

	err := s.Register("slow-job", "@every 1s", func(context.Context) error {
		runs.Add(1)
		time.Sleep(2 * time.Second)
		return nil
	})
	if err != nil {
		t.Fatalf("register slow job: %v", err)
	}

	s.Start()
	time.Sleep(2200 * time.Millisecond)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Stop(stopCtx); err != nil {
		t.Fatalf("stop scheduler: %v", err)
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
