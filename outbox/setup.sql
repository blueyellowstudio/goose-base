-- Outbox Events table for transactional outbox pattern
CREATE TABLE outbox_events
(
    id           uuid PRIMARY KEY,
    event_type   text        NOT NULL,
    payload      jsonb       NOT NULL,
    occurred_at  timestamptz NOT NULL,
    processed_at timestamptz NULL,
    retry_count  integer     NOT NULL DEFAULT 0,
    last_error   text        NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_outbox_unprocessed
    ON outbox_events (occurred_at)
    WHERE processed_at IS NULL;

-- Dead letter events for failed processing
CREATE TABLE outbox_dead_letter_events
(
    id                uuid PRIMARY KEY,
    original_event_id uuid        NOT NULL,
    event_type        text        NOT NULL,
    payload           jsonb       NOT NULL,
    occurred_at       timestamptz NOT NULL,
    failed_at         timestamptz NOT NULL DEFAULT now(),
    retry_count       integer     NOT NULL,
    last_error        text        NOT NULL
);