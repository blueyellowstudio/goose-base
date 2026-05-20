# Scheduler

The scheduler is a simple cron-like scheduler that runs jobs in the background.

## Usage

The scheduler uses cron expressions like `*/10 * * * *` or `@every 10m`.


### Example
```go
package main

import (
    "context"
    "log/slog"
    "time"
    
    "github.com/blueyellowstudio/goose-base/scheduler"
)

func main() {
    logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
    s := scheduler.New(logger)
    
    // Register a job that runs every 5 minutes
    s.Register("cleanup", "*/5 * * * *", func(ctx context.Context) error {
        // Your cleanup logic here
        slog.InfoContext(ctx, "Running cleanup job")
        return nil
    })
    
    // Start the scheduler
    s.Start()
    
    // Keep the program running
    select {}
}
```