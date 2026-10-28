# storage

`storage/` abstracts file storage behind the `Storage` interface (upload/download URLs, delete, list, info).

## Backends

| Backend | Package | Notes |
|---|---|---|
| `FileStorage` | `storage` | Local filesystem, HMAC-signed URLs. |
| `SupabaseStorage` | `storage` | Supabase Storage API. |
| `s3storage.Storage` | `storage/s3storage` | Any S3-compatible service (Supabase S3 protocol, SeaweedFS, AWS). |

`s3storage` is a sub-package: only an importer of it builds the AWS SDK; `storage` itself has no AWS dependency.

## SignedStorage

`SignedStorage` extends `Storage` and is implemented by `s3storage.Storage` only, because only S3 presigning can bind a content type and response headers into the signature:

- `PresignUpload`: a PUT URL plus the exact headers the client must send (`Content-Type` is signed; a different type is refused with 403).
- `PresignDownload`: a GET URL with `Content-Disposition` (inline or attachment, RFC 5987 file name) and optional `Cache-Control`.
- `HeadObject`: size, content type, modification time; a missing object returns `ErrObjectNotFound`.
- `DeleteObjectContext`: deletes with the caller's deadline; a missing key is not an error.

`ttl <= 0` uses the configured default.

## Configuration of `s3storage.New`

| Field | Default |
|---|---|
| `Endpoint` | required |
| `AccessKey`, `SecretKey` | required |
| `Region` | `us-east-1` |
| `UploadExpiry` | 15 min |
| `DownloadExpiry` | 1 h |

Only the given values are used; ambient AWS environment variables and config files are ignored.

### One endpoint

SigV4 signs the host. Configure the public URL the browser calls (for example `https://<host>/storage/v1/s3`), never an internal host such as `supabase-storage:5000`; the presigned URLs name this endpoint and would not validate otherwise.

### Checksums

Request and response checksums are only used when required (`WhenRequired`); Supabase does not support the default checksum headers.

### Deleting

`DeleteObject`, `DeleteObjects` and `DeleteObjectContext` treat a missing key (`NoSuchKey`) as success. A missing bucket stays an error.

## Tests

`storage/s3storage` tests start SeaweedFS 4.51 as a testcontainer. To use another server set `GOOSE_S3_TEST_ENDPOINT`, `GOOSE_S3_TEST_ACCESS_KEY`, `GOOSE_S3_TEST_SECRET_KEY` and `GOOSE_S3_TEST_BUCKET`.
