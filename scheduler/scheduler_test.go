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

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
