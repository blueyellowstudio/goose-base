# medialib — Semi-Public Media Asset Library

Reusable, entity-agnostic media asset management. Assets are **semi-public**:
visible to any logged-in user and identical for all of them. Storage and on-the-fly
image resizing are delegated to **Supabase**; the library owns the asset lifecycle
(upload via presigned URL, re-upload, a single active object per asset, soft/hard
deletion, and a deletion trail for client cache invalidation).

The library knows nothing about the application entities that reference its media —
those links live on app-side tables (e.g. an `exercise_media` table).

## Components

| File / dir | Purpose |
|---|---|
| `media.go` | `Service` — public API orchestration |
| `config.go` | `Tables` (dynamic table names) + defaults |
| `url.go` | `URLBuilder` — Supabase render/object URL building |
| `domain/` | `Media`, `MediaObject`, `MediaWithActiveObject`, `MediaObjectDeletion` + repository interfaces |
| `postgres/` | default pgx repository implementations |
| `migrations/1.sql`, `provisioning.sql` | reference schema (tables, indexes, constraints) |

## Access model

- **Semi-public** is a coarse gate ("is this a valid logged-in session"), not
  per-file ownership. Reads are gated by Supabase **RLS** (an authenticated-read
  policy on the bucket).
- Reads come in two shapes, differing only in *where the credential lives*:
  - `GetActiveURL` / `ResolveActiveURLs` → an `…/authenticated/…` URL. The
    **caller** attaches the Supabase JWT as an `Authorization` header. Supports
    on-the-fly image resizing.
  - `GetActiveSignedURL` → a signed URL carrying its own short-lived token in the
    query string. For clients that **cannot** set that header — a browser holding
    its session in an HttpOnly cookie, since Supabase's storage API reads the
    bearer token from the `Authorization` header only and never from a cookie.
    Usable directly as an `<img>`/`<video>` src, and supports **range requests**,
    so video seeking works. No image transform: Supabase applies transforms at
    signing time and this does not pass one, so you get the original.
- Signing uses the **service role key**, which bypasses RLS. Not an escalation
  here — it grants exactly what the authenticated-read policy already grants every
  logged-in user. Callers are still expected to have a session of their own.
- Writes are never client-credentialed. Uploads (presigned), HEAD checks
  (`FileExists` / `GetObjectInfo`) and deletes are performed by the backend using the
  Supabase **service role key**, which **bypasses RLS**.

## Storage layout

The injected `Storage` receives the object key verbatim; the library builds it as:

```
<bucket>/
  <storage_key>/
    <media_object_id>/original.<ext>
```

`<ext>` comes from the `extension` supplied at create-upload time (no mime→ext
guessing).

## URL resolution

`Service.GetActiveURL` returns a fully-built read URL for a media's active object:

- **Image types** → the Supabase **render** URL
  `…/render/image/authenticated/<bucket>/<path>`.
  No query param ⇒ the original; the app appends `?width=<n>` ⇒ a resized image,
  generated on the fly and edge-cached.
- **Other types** (e.g. video) → the plain object URL
  `…/object/authenticated/<bucket>/<path>`. `width` does not apply.

Which `media.type` values are treated as images is configurable via
`NewURLBuilder(base, bucket, imageTypes)` (defaults to `{"image"}`).

> The `…/authenticated/…` endpoints require the **caller** (e.g. the mobile image
> loader) to attach the Supabase JWT: `Authorization: Bearer <jwt>` and `apikey`.

### Batch resolution

`Service.ResolveActiveURLs(ctx, mediaIDs)` resolves the asset **type** and active
read URL for many media in a **single** query — `media` LEFT JOINed to its active
object — returning `map[uuid.UUID]ResolvedMedia`. `GetActiveURL` issues two reads
per call (the media row, then its active object), so resolving N media one-by-one
is `N×2` queries; prefer `ResolveActiveURLs` to resolve a whole page at once.

```go
type ResolvedMedia struct {
    Type      string // media.type, even when no object is active
    URL       string // active read URL; empty when HasActive is false
    HasActive bool   // whether an active object exists
}
```

- Input ids are de-duplicated; an empty slice yields an empty map.
- Media with **no active object** are present with `Type` set, `HasActive: false`
  and an empty `URL` (the batch analogue of `GetActiveURL`'s `ErrNoActiveObject`).
- **Missing** media ids are simply absent from the map.

The underlying read is `MediaRepository.ListWithActiveObjectByIDs`, which returns
`[]MediaWithActiveObject` — each `Media` paired with its active `*MediaObject`
(`nil` when none). `GetActiveURL` / `GetMedia` remain for single-item paths.

---

## Supabase bucket & RLS setup

The library requires **one private bucket** with an authenticated-read RLS policy.
Replace `<bucket>` with your bucket name.

### 1. Create a private bucket

A **private** bucket (not public) so that reads are gated by RLS.

```sql
insert into storage.buckets (id, name, public)
values ('<bucket>', '<bucket>', false)
on conflict (id) do nothing;
```

(Or via the dashboard: Storage → New bucket → name `<bucket>`, **Public = off**.)

### 2. Authenticated-read policy

Any logged-in user may read any object in the bucket (this is the "semi-public"
gate). This is the **only client-facing policy needed**.

```sql
create policy "<bucket>_authenticated_read"
  on storage.objects
  for select
  to authenticated
  using ( bucket_id = '<bucket>' );
```

### 3. No insert / update / delete policies needed

Writes are never performed with client credentials:

- **Uploads** — the backend mints a one-time presigned upload URL
  (`GenerateUploadURL`, signed with the service role); the client PUTs to that URL.
  The signed token authorizes the single upload and bypasses RLS.
- **Activation HEAD checks & deletes** — done by the backend with the service role
  key, which bypasses RLS.

So clients need **no** `insert`/`update`/`delete` privileges on `storage.objects`
for this bucket.

### 4. Image transformations (for `?width=`)

The `…/render/image/…` endpoints require Supabase **Image Transformations**
(Supabase Pro plan, or self-hosted with the imgproxy service enabled). If
transformations are unavailable, configure no image types so every media resolves
to the plain `…/object/authenticated/…` URL.

---

## Wiring

```go
import (
    "github.com/blueyellowstudio/goose-base/medialib"
    mlpg "github.com/blueyellowstudio/goose-base/medialib/postgres"
    "github.com/blueyellowstudio/goose-base/storage"
    pgxrunner "github.com/blueyellowstudio/goose-base/tx/pgxrunner"
)

base := supabaseURL + "/storage/v1" // e.g. https://<proj>.supabase.co/storage/v1

store, _ := storage.NewSupabaseStorage(&storage.SupabaseStorageConfig{
    StorageURL:       base,
    StoragePublicURL: base,
    ServiceKey:       serviceRoleKey,
    UploadExpiry:     15 * time.Minute, // signed upload TTL
})

tables := medialib.NewDefaultTables() // media / media_objects / media_objects_deletions
svc := medialib.NewService(
    pgxrunner.NewRunner(pool),
    mlpg.NewMediaRepository(pool, tables),
    mlpg.NewMediaObjectRepository(pool, tables),
    mlpg.NewDeletionRepository(pool, tables),
    store,
    medialib.NewURLBuilder(base, bucket, nil),
    bucket,
    nil, // slog.Default()
)
```

## Upload flow

1. `CreateMedia(storageKey, type)` → media row (empty `storageKey` defaults to the
   media id).
2. `CreateMediaObject(mediaID, mime, ext, sizeBytes)` → pending object + presigned
   upload URL for `<storage_key>/<object_id>/original.<ext>`.
3. Client PUTs the file directly to the presigned URL.
4. `ActivateMediaObject(objectID, sizeBytes)` → verifies the upload landed
   (`FileExists`), overwrites `size_bytes` with the real size, and activates it,
   superseding the prior active object within a media-row-locked transaction.

The "at most one active object per media" rule is enforced both in the activation
transaction and by a **partial unique index** in the schema.
