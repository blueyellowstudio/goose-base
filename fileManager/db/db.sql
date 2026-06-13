CREATE EXTENSION IF NOT EXISTS ltree;
-- 1. languages table
CREATE TABLE IF NOT EXISTS languages
(
    id       SERIAL PRIMARY KEY,
    name     VARCHAR(100) NOT NULL,
    iso_code VARCHAR(10)  NOT NULL
);

CREATE TABLE folders
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    path       ltree       NOT NULL,
    parent_id  UUID REFERENCES folders (id),
    name       TEXT        NOT NULL,
    name_ref   UUID REFERENCES translations (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID        NOT NULL REFERENCES "user" (id),
    deleted_at TIMESTAMPTZ,
    metadata   JSONB       NOT NULL DEFAULT '{}'
);
CREATE INDEX folders_path_gist ON folders USING GIST (path);
CREATE INDEX folders_parent_id_idx ON folders (parent_id);

CREATE TABLE files
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    folder_id  UUID        NOT NULL REFERENCES folders (id),
    name       TEXT        NOT NULL,
    name_ref   UUID REFERENCES translations (id),
    user_id    UUID        NOT NULL REFERENCES "user" (id),
    file_type  TEXT,
    category   INT,
    mime_type  TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    metadata   JSONB       NOT NULL DEFAULT '{}'
);
CREATE INDEX files_folder_id_idx ON files (folder_id);

CREATE TABLE file_objects
(
    id           UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    file_id      UUID        NOT NULL REFERENCES files (id),
    name         TEXT        NOT NULL,
    language_id  INT REFERENCES languages (id),
    is_available BOOLEAN     NOT NULL DEFAULT false,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ,
    metadata     JSONB       NOT NULL DEFAULT '{}'
);
CREATE INDEX file_objects_file_id_idx ON file_objects (file_id);

ALTER TABLE public.file_objects
    ADD CONSTRAINT file_objects_pk
        UNIQUE NULLS NOT DISTINCT (file_id, language_id);

CREATE TABLE stored_files
(
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    file_obj_id UUID        NOT NULL REFERENCES file_objects (id),
    file_size   BIGINT,
    status      TEXT        NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);
CREATE INDEX stored_files_file_obj_id_idx ON stored_files (file_obj_id);
CREATE INDEX stored_files_status_idx ON stored_files (status) WHERE deleted_at IS NULL;

-- Deletion log (tombstones) for offline sync: records files and file objects as they
-- are soft-deleted so clients can purge locally cached copies.
CREATE TABLE deleted_items
(
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    entity_type TEXT        NOT NULL,
    entity_id   UUID        NOT NULL,
    file_id     UUID        NOT NULL,
    deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX deleted_items_deleted_at_idx ON deleted_items (deleted_at);