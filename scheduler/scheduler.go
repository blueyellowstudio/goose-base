package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"
)

const defaultJobTimeout = 9 * time.Minute

// Scheduler registers cron-like jobs and runs them in-process.
type Scheduler struct {
	cron       *cron.Cron
	logger     *slog.Logger
	jobTimeout time.Duration
}

// New creates a scheduler with panic recovery and skip-if-running overlap handling.
func New(logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}

	cronLogger := cronLogAdapter{logger: logger}
	return &Scheduler{
		cron: cron.New(
			cron.WithLogger(cronLogger),
			cron.WithChain(
				cron.Recover(cronLogger),
				cron.SkipIfStillRunning(cronLogger),
			),
		),
		logger:     logger,
		jobTimeout: defaultJobTimeout,
	}
}

// Register adds a named job for a cron expression such as "*/10 * * * *" or "@every 10m".
func (s *Scheduler) Register(name string, spec string, fn func(context.Context) error) error {
	if name == "" {
		return fmt.Errorf("register scheduler job: name is required")
	}
	if fn == nil {
		return fmt.Errorf("register scheduler job %q: function is required", name)
	}

	_, err := s.cron.AddFunc(spec, s.wrapJob(name, fn))
	if err != nil {
		return fmt.Errorf("register scheduler job %q: %w", name, err)
	}

	s.logger.Info("scheduler job registered", "job", name, "spec", spec)
	return nil
}

// Start begins executing registered jobs in the background.
func (s *Scheduler) Start() {
	s.cron.Start()
	s.logger.Info("scheduler started")
}

// Stop stops scheduling new runs and waits for active jobs or the provided context.
func (s *Scheduler) Stop(ctx context.Context) error {
	runningJobsDone := s.cron.Stop()

	select {
	case <-runningJobsDone.Done():
		s.logger.Info("scheduler stopped")
		return nil
	case <-ctx.Done():
		return fmt.Errorf("stop scheduler: %w", ctx.Err())
	}
}

func (s *Scheduler) wrapJob(name string, fn func(context.Context) error) func() {
	return func() {
		startedAt := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), s.jobTimeout)
		defer cancel()

		s.logger.Info("scheduler job started", "job", name)
		if err := fn(ctx); err != nil {
			s.logger.Error("scheduler job failed", "job", name, "duration", time.Since(startedAt).String(), "error", err)
			return
		}
		s.logger.Info("scheduler job completed", "job", name, "duration", time.Since(startedAt).String())
	}
}

type cronLogAdapter struct {
	logger *slog.Logger
}

func (l cronLogAdapter) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, keysAndValues...)
}

func (l cronLogAdapter) Error(err error, msg string, keysAndValues ...interface{}) {
	args := append(keysAndValues, "error", err)
	l.logger.Error(msg, args...)
}
