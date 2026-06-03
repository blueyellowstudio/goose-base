-- ============================================================================
-- medialib provisioning (standalone reference)
-- ============================================================================
-- Tables, indexes and constraints for the semi-public media asset library.
-- Table names here use medialib's defaults; consuming apps may rename them via
-- medialib.Tables and should mirror these definitions in their own migrations.
--
-- Access model: semi-public. Reads are gated by Supabase RLS (authenticated-read
-- policy on the bucket), not by library-side signing. The library issues
-- presigned URLs only for uploads.
-- ============================================================================

-- media — the logical asset slot. Carries no application meaning (name,
-- description, …); those live on app-side link tables.
CREATE TABLE media
(
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    storage_key TEXT        NOT NULL, -- prefix grouping a media's objects
    type        TEXT        NOT NULL, -- app-defined (image, video, …)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ            -- soft delete
);

-- media_objects — the physical upload. The storage object URL is derived from
-- the object id at runtime. Re-upload = a new row against an existing media_id.
CREATE TABLE media_objects
(
    id                UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    media_id          UUID        NOT NULL REFERENCES media (id),
    status            TEXT        NOT NULL DEFAULT 'pending',  -- pending → active → deleted
    processing_status TEXT        NOT NULL DEFAULT 'pending',  -- pending → processing → done → failed (video posters; future)
    size_bytes        BIGINT,                                  -- sent by frontend, overwritten with actual on activation
    mime_type         TEXT,
    extension         TEXT,                                    -- sent at create-time; used to build the object path
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at        TIMESTAMPTZ
);
CREATE INDEX media_objects_media_id_idx ON media_objects (media_id);

-- Exactly one active object per media (enforced at the DB, not just in app code).
-- Activation supersedes the prior active object (status=deleted) within the same
-- media-row-locked transaction, so this index never sees two active rows.
CREATE UNIQUE INDEX media_objects_one_active
    ON media_objects (media_id) WHERE status = 'active' AND deleted_at IS NULL;

-- media_objects_deletions — the deletion trail. Written on hard delete; clients
-- pull entries after a timestamp to purge stale cache entries for removed objects.
CREATE TABLE media_objects_deletions
(
    id              UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    media_object_id UUID        NOT NULL, -- correlation key (the deleted object's id)
    storage_path    TEXT        NOT NULL, -- full path removed from storage
    deleted_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX media_objects_deletions_deleted_at_idx ON media_objects_deletions (deleted_at);
CREATE INDEX media_objects_deletions_object_id_idx ON media_objects_deletions (media_object_id);
