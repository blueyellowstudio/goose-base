-- medialib schema (reference). Table names match medialib.NewDefaultTables().
-- See ../../provisioning.sql for the same definitions with commentary.

CREATE TABLE media
(
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    storage_key TEXT        NOT NULL,
    type        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);

CREATE TABLE media_objects
(
    id                UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    media_id          UUID        NOT NULL REFERENCES media (id),
    status            TEXT        NOT NULL DEFAULT 'pending',
    processing_status TEXT        NOT NULL DEFAULT 'pending',
    size_bytes        BIGINT,
    mime_type         TEXT,
    extension         TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at        TIMESTAMPTZ
);
CREATE INDEX media_objects_media_id_idx ON media_objects (media_id);

-- At most one active object per media (DB guarantee, not just app logic).
CREATE UNIQUE INDEX media_objects_one_active
    ON media_objects (media_id) WHERE status = 'active' AND deleted_at IS NULL;

CREATE TABLE media_objects_deletions
(
    id              UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    media_object_id UUID        NOT NULL,
    storage_path    TEXT        NOT NULL,
    deleted_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX media_objects_deletions_deleted_at_idx ON media_objects_deletions (deleted_at);
CREATE INDEX media_objects_deletions_object_id_idx ON media_objects_deletions (media_object_id);
