# File Manager — HTTP Handler

The `fileManager/handler` package provides ready-made HTTP handlers that wire directly onto the `fileManager.Service`. It covers standard CRUD operations for folders, files, and file objects (including the upload/activate lifecycle), file download endpoints, and folder-content browsing — all with pluggable access control so each consuming project can inject its own authorization logic.

---

## Package overview

```
fileManager/handler/
├── context.go        # UserID context key + InjectUserIDMiddleware
├── handler.go        # Handler struct + HandlerOverrides
├── routes.go         # Routers struct + RegisterRoutes
├── download.go       # DownloadHandler + FileAccessChecker
├── browse.go         # BrowseHandler + FolderAccessResolver + FileEnricher
├── folders.go        # createFolder, renameFolder, softDeleteFolder, moveFolder, getFolderBreadcrumbs
├── files.go          # softDeleteFile, moveFile
├── file_objects.go   # createFileObject, updateFileObject, softDeleteFileObject, getUploadURL, activateStoredFile
└── dto/
    └── types.go      # Request / response types used by the library handlers
```

---

## Concepts

### Routers

Route registration splits endpoints across three routers so the consuming project controls the access level per verb:

```go
type Routers struct {
    Read   chi.Router // GET endpoints
    Create chi.Router // POST endpoints
    Update chi.Router // PATCH / PUT / DELETE endpoints
}
```

Pass the same router for multiple fields if your project does not need a distinction.

### HandlerOverrides

Three endpoints (`CreateFile`, `GetFile`, `UpdateFile`) commonly require project-specific logic — e.g. setting access records alongside the file. Pass your own `http.HandlerFunc` for each; if a field is `nil` the route is simply not registered and the project is responsible for registering it separately (or omitting it entirely).

```go
type HandlerOverrides struct {
    CreateFile http.HandlerFunc
    GetFile    http.HandlerFunc
    UpdateFile http.HandlerFunc
}
```

### UserID middleware

The library handlers need the authenticated user's UUID to populate `CreatedBy` fields. Because the library is auth-agnostic, it reads the ID from the request context via a typed key. Use `InjectUserIDMiddleware` to bridge any project-level auth claim into that key:

```go
middleware := handler.InjectUserIDMiddleware(func(r *http.Request) (uuid.UUID, bool) {
    claims := myauth.GetClaims(r.Context())
    if claims == nil {
        return uuid.UUID{}, false
    }
    return claims.UserID, true
})
```

Apply this middleware to whichever routers you pass to `RegisterRoutes`. If the ID is missing at handler time the library returns `401 Unauthorized`.

### DownloadHandler

`DownloadHandler` provides the three file-download endpoints. Because deciding whether a caller may access a file is always project-specific (public availability flags, company roles, elevated users, etc.), the handler accepts a `FileAccessChecker` function at construction time:

```go
// FileAccessChecker reports whether the incoming request may access the given file.
// Returns (allowed, httpStatusCode, error). statusCode is only meaningful on denial.
type FileAccessChecker func(r *http.Request, fileID uuid.UUID) (bool, int, error)

func NewDownloadHandler(service *fileManager.Service, checkAccess FileAccessChecker) *DownloadHandler

// RegisterDownloadRoutes registers the three endpoints:
//   publicRouter — GetFileDownloadMeta, GetFileDownloadURL
//   authRouter   — GetDownloadURL
func (h *DownloadHandler) RegisterDownloadRoutes(publicRouter, authRouter chi.Router)
```

The project implements `FileAccessChecker` with its own access repository, user-role checks, and public-availability logic, then passes it in. The handler logic itself is identical across projects.

### BrowseHandler

`BrowseHandler` provides paginated folder-content listing. It uses two injectable functions:

**`FolderAccessResolver`** — derives the `domain.AccessFilter` from the request. The project reads any URL params it needs (e.g. a company ID) directly from `r` using `chi.URLParam`. Returns the filter or an HTTP error status.

```go
type FolderAccessResolver func(r *http.Request) (domain.AccessFilter, int, error)
```

**`FileEnricher`** — optionally transforms raw `[]domain.FileWithObject` results before they are JSON-encoded. Pass `nil` to encode the raw domain slice directly. When non-nil the returned `json.RawMessage` replaces the `files` field in the response — this lets the project append device-access records, company-access info, or any other per-file enrichment without the library knowing those types.

```go
type FileEnricher func(ctx context.Context, files []domain.FileWithObject) (json.RawMessage, error)

func NewBrowseHandler(
    service       *fileManager.Service,
    resolveAccess FolderAccessResolver,
    enrichFiles   FileEnricher, // nil = encode []domain.FileWithObject directly
) *BrowseHandler

// RegisterBrowseRoutes registers:
//   GET /documents
//   GET /documents/folders/{folderID}
//   GET /documents/folders/{folderID}/files
// Mount the router under a project-specific prefix before calling this,
// e.g. r.Route("/companies/{companyID}", func(r chi.Router) { browseHandler.RegisterBrowseRoutes(r) })
func (h *BrowseHandler) RegisterBrowseRoutes(r chi.Router)
```

---

## API Reference

### Browse

---

#### `GET /documents`

Return a page of root-level folders and files visible to the requesting user.
The actual full path depends on where the project mounts the router (e.g. `/companies/{companyID}/documents`).

**Query params**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Page size, capped at 200 |
| `folderCursor` | string | — | Opaque cursor from a previous response |
| `fileCursor` | string | — | Opaque cursor from a previous response |
| `search` | string | — | Case-insensitive substring filter on name |

**Response `200 OK`**

```json
{
  "folders": [ { ...Folder } ],
  "folderNextCursor": "string",   // omitted if no next page
  "files": [ ...enriched by FileEnricher ],
  "fileNextCursor": "string"      // omitted if no next page
}
```

---

#### `GET /documents/folders/{folderID}`

Return a page of immediate children (folders + files) of a folder.

**Path params** — `folderID: uuid`

**Query params** — same as above.

**Response `200 OK`** — same shape as above.

---

#### `GET /documents/folders/{folderID}/files`

Return a page of **files only** in a folder (no subfolders).

**Path params** — `folderID: uuid`

**Query params**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Page size, capped at 200 |
| `fileCursor` | string | — | Opaque cursor from a previous response |
| `search` | string | — | Case-insensitive substring filter on name |

**Response `200 OK`**

```json
{
  "files": [ ...enriched by FileEnricher ],
  "fileNextCursor": "string"      // omitted if no next page
}
```

---

### Download

---

#### `GET /documents/files/{fileID}/downloadMeta`

Return file-level download metadata for the best-matching language variant.

**Path params** — `fileID: uuid`

**Query params** — `languageId: int` (optional)

**Response `200 OK`**

```json
{
  "name": "string",
  "fileExtension": "string",
  "fileType": "string",         // omitted if not set
  "fileSize": 12345,            // omitted if not set
  "fileUpdatedAt": "RFC3339",
  "metaUpdatedAt": "RFC3339",
  "languageId": 1               // omitted if not set
}
```

**Error responses**

| Status | Condition |
|--------|-----------|
| `400 Bad Request` | Invalid `fileID` or `languageId` |
| `401 Unauthorized` | Access check returned unauthorized |
| `403 Forbidden` | Access check returned forbidden |
| `404 Not Found` | File or its active stored file not found |

---

#### `GET /documents/files/{fileID}/getUrl`

Return a pre-signed download URL for the best-matching language variant.

**Path params** — `fileID: uuid`

**Query params** — `languageId: int` (optional), `download: bool` (optional, default `false`)

**Response `200 OK`**

```json
{ "url": "string" }
```

**Error responses** — same as `downloadMeta`.

---

#### `GET /documents/files/{fileID}/objects/{objectID}/download-url`

Return a pre-signed download URL for a specific file object (language variant).

**Path params** — `fileID: uuid`, `objectID: uuid`

**Query params** — `download: bool` (optional, default `false`)

**Response `200 OK`**

```json
{ "url": "string" }
```

**Error responses**

| Status | Condition |
|--------|-----------|
| `400 Bad Request` | Invalid `objectID` |
| `401/403` | Access check denied |
| `404 Not Found` | File object or stored file not found |

---

### Folders

---

#### `POST /documents/folders`

Create a new folder.

**Request body**

```json
{
  "name": "string",           // required
  "parentId": "uuid"          // optional — omit for a root folder
}
```

**Response `201 Created`**

```json
{
  "id": "uuid",
  "path": "string",
  "parentID": "uuid",         // omitted if root
  "name": "string",
  "nameRef": "uuid",          // omitted if not set
  "createdAt": "RFC3339",
  "createdBy": "uuid",
  "deletedAt": "RFC3339",     // omitted if not deleted
  "metadata": {}
}
```

---

#### `PATCH /documents/folders/{folderID}`

Rename a folder.

**Path params** — `folderID: uuid`

**Request body**

```json
{ "name": "string" }
```

**Response `204 No Content`**

---

#### `DELETE /documents/folders/{folderID}`

Soft-delete a folder.

**Path params** — `folderID: uuid`

**Response `204 No Content`**

---

#### `POST /documents/folders/{folderID}/move`

Move a folder to a new parent.

**Path params** — `folderID: uuid`

**Request body**

```json
{ "newParentId": "uuid" }     // null to move to root
```

**Response `204 No Content`**

---

#### `GET /documents/folders/{folderID}/ancestors`

Return the ancestor chain (breadcrumbs) from root down to the given folder.

**Path params** — `folderID: uuid`

**Response `200 OK`**

```json
[ { "id": "uuid", "name": "string" }, ... ]
```

---

### Files

> `POST /documents/files`, `GET /documents/files/{fileID}`, and `PATCH /documents/files/{fileID}` are **override-only** — registered only when the corresponding `HandlerOverrides` field is non-nil. Request/response shapes are project-defined.

---

#### `DELETE /documents/files/{fileID}`

Soft-delete a file.

**Path params** — `fileID: uuid`

**Response `204 No Content`**

---

#### `POST /documents/files/{fileID}/move`

Move a file to a different folder.

**Path params** — `fileID: uuid`

**Request body**

```json
{ "newFolderId": "uuid" }     // null to move to root
```

**Response `204 No Content`**

---

### File Objects

---

#### `POST /documents/files/{fileID}/objects`

Create a new file object (language/variant slot).

**Path params** — `fileID: uuid`

**Request body**

```json
{
  "name": "string",
  "originalFileName": "string",
  "languageId": 1             // optional
}
```

**Response `201 Created`**

```json
{
  "id": "uuid",
  "fileId": "uuid",
  "name": "string",
  "originalFileName": "string",
  "languageId": 1,
  "isAvailable": false,
  "updatedAt": "RFC3339",
  "deletedAt": "RFC3339",
  "metadata": {}
}
```

---

#### `PUT /documents/files/{fileID}/objects/{objectID}`

Update a file object's metadata.

**Request body**

```json
{
  "name": "string",
  "languageId": 1,
  "originalFileName": "string"
}
```

**Response `204 No Content`**

---

#### `DELETE /documents/files/{fileID}/objects/{objectID}`

Soft-delete a file object.

**Response `204 No Content`**

---

#### `GET /documents/files/{fileID}/objects/{objectID}/upload-url`

Generate a pre-signed upload URL. Also creates a pending `StoredFile`.

**Response `200 OK`**

```json
{
  "url": "string",
  "storedFileId": "uuid"
}
```

---

#### `POST /documents/files/{fileID}/objects/{objectID}/stored-files/{storedFileID}/activate`

Mark an uploaded stored file as active. Supersedes the previous active version and flips `isAvailable` on the parent file object.

**Response `204 No Content`**

---

### Route / router matrix

| Handler | Router | Method | Path |
|---------|--------|--------|------|
| BrowseHandler | project-defined | GET | `/documents` (relative to mount prefix) |
| BrowseHandler | project-defined | GET | `/documents/folders/{folderID}` (relative to mount prefix) |
| BrowseHandler | project-defined | GET | `/documents/folders/{folderID}/files` (relative to mount prefix) |
| DownloadHandler | public (optional auth) | GET | `/documents/files/{fileID}/downloadMeta` |
| DownloadHandler | public (optional auth) | GET | `/documents/files/{fileID}/getUrl` |
| DownloadHandler | auth | GET | `/documents/files/{fileID}/objects/{objectID}/download-url` |
| Handler (via RegisterRoutes) | Create | POST | `/documents/folders` |
| Handler (via RegisterRoutes) | Update | PATCH | `/documents/folders/{folderID}` |
| Handler (via RegisterRoutes) | Update | DELETE | `/documents/folders/{folderID}` |
| Handler (via RegisterRoutes) | Update | POST | `/documents/folders/{folderID}/move` |
| Handler (via RegisterRoutes) | Read | GET | `/documents/folders/{folderID}/ancestors` |
| Handler (via RegisterRoutes) | Create | POST | `/documents/files` | override only |
| Handler (via RegisterRoutes) | Read | GET | `/documents/files/{fileID}` | override only |
| Handler (via RegisterRoutes) | Update | PATCH | `/documents/files/{fileID}` | override only |
| Handler (via RegisterRoutes) | Update | DELETE | `/documents/files/{fileID}` |
| Handler (via RegisterRoutes) | Update | POST | `/documents/files/{fileID}/move` |
| Handler (via RegisterRoutes) | Create | POST | `/documents/files/{fileID}/objects` |
| Handler (via RegisterRoutes) | Update | PUT | `/documents/files/{fileID}/objects/{objectID}` |
| Handler (via RegisterRoutes) | Update | DELETE | `/documents/files/{fileID}/objects/{objectID}` |
| Handler (via RegisterRoutes) | Update | GET | `/documents/files/{fileID}/objects/{objectID}/upload-url` |
| Handler (via RegisterRoutes) | Update | POST | `/documents/files/{fileID}/objects/{objectID}/stored-files/{storedFileID}/activate` |

---

## Usage example

The example below shows a project that splits routes across `companyReadRouter` (browse), `publicRouter` (download meta/URL), `authRouter` (authenticated downloads + CRUD reads), and `elevatedRouter` (mutations). The project injects its own `checkAccess` and `resolveAccess` functions.

```go
package document

import (
    "context"
    "encoding/json"
    "errors"
    "net/http"

    "myproject/internal/authorization"
    "myproject/internal/db/documents"
    "myproject/internal/domain"

    "github.com/blueyellowstudio/goose-base/fileManager"
    fmhandler "github.com/blueyellowstudio/goose-base/fileManager/handler"
    fileManagerDomain "github.com/blueyellowstudio/goose-base/fileManager/domain"
    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

type Handler struct {
    service         *fileManager.Service
    accessRepo      *documents.AccessRepository
    lib             *fmhandler.Handler
    downloadHandler *fmhandler.DownloadHandler
    browseHandler   *fmhandler.BrowseHandler
}

func NewHandler(service *fileManager.Service, accessRepo *documents.AccessRepository) *Handler {
    h := &Handler{service: service, accessRepo: accessRepo}

    h.lib = fmhandler.NewHandler(service, fmhandler.HandlerOverrides{
        CreateFile: h.CreateFile,
        GetFile:    h.GetFile,
        UpdateFile: h.UpdateFile,
    })

    h.downloadHandler = fmhandler.NewDownloadHandler(service, h.checkFileAccess)

    h.browseHandler = fmhandler.NewBrowseHandler(
        service,
        h.resolveFolderAccess,
        h.enrichFiles,
    )

    return h
}

func (h *Handler) MountRoutes(
    companyReadRouter chi.Router,
    publicRouter      chi.Router,
    authRouter        chi.Router,
    elevatedRouter    chi.Router,
) {
    withUserID := fmhandler.InjectUserIDMiddleware(func(r *http.Request) (uuid.UUID, bool) {
        if c := authorization.GetUserClaims(r.Context()); c != nil {
            return c.UserID, true
        }
        return uuid.UUID{}, false
    })

    h.lib.RegisterRoutes(fmhandler.Routers{
        Read:   authRouter.With(withUserID),
        Create: elevatedRouter.With(withUserID),
        Update: elevatedRouter.With(withUserID),
    })

    companyReadRouter.Route("/companies/{companyID}", func(r chi.Router) {
        h.browseHandler.RegisterBrowseRoutes(r)
    })
    h.downloadHandler.RegisterDownloadRoutes(publicRouter, authRouter)
}

// checkFileAccess is the FileAccessChecker — project-specific logic lives here.
func (h *Handler) checkFileAccess(r *http.Request, fileID uuid.UUID) (bool, int, error) {
    // 1. public availability via device access records
    access, _ := h.accessRepo.ListDeviceAccess(r.Context(), fileID)
    for _, a := range access {
        if a.UserLevel == 0 {
            return true, 0, nil
        }
    }
    // 2. authenticated user check
    claims := authorization.GetUserClaims(r.Context())
    if claims == nil {
        return false, http.StatusUnauthorized, errors.New("unauthorized")
    }
    allowed, err := h.accessRepo.IsUserAllowedToAccessFile(r.Context(), fileID, claims.UserID)
    if err != nil {
        return false, http.StatusInternalServerError, err
    }
    if !allowed {
        return false, http.StatusForbidden, nil
    }
    return true, http.StatusOK, nil
}

// resolveFolderAccess is the FolderAccessResolver — reads companyID from the URL,
// then derives the AccessFilter from the user's company role.
func (h *Handler) resolveFolderAccess(r *http.Request) (fileManagerDomain.AccessFilter, int, error) {
    companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
    if err != nil {
        return nil, http.StatusBadRequest, errors.New("invalid company id")
    }
    claims := authorization.GetUserClaims(r.Context())
    if claims == nil {
        return nil, http.StatusUnauthorized, errors.New("unauthorized")
    }
    role, err := h.accessRepo.GetCompanyRole(r.Context(), claims.UserID, companyID)
    if err != nil || role == nil {
        return nil, http.StatusForbidden, errors.New("forbidden")
    }
    return domain.CompanyLevelFilter{Hierarchy: role.Hierarchy}, 0, nil
}

// enrichFiles is the FileEnricher — appends project-specific access data.
func (h *Handler) enrichFiles(ctx context.Context, files []fileManagerDomain.FileWithObject) (json.RawMessage, error) {
    type enriched struct {
        fileManagerDomain.File
        DeviceAccess []documents.DeviceDocumentAccess `json:"deviceAccess"`
    }
    result := make([]enriched, len(files))
    for i, f := range files {
        access, err := h.accessRepo.ListDeviceAccess(ctx, f.ID)
        if err != nil {
            return nil, err
        }
        result[i] = enriched{File: f.File, DeviceAccess: access}
    }
    return json.Marshal(result)
}
```

---

## What stays in the project

The following endpoints are always project-specific and must be registered by the consuming project directly:

| Endpoint | Reason |
|----------|--------|
| `POST /documents/files/{fileID}/access/device` | Writes to project's `AccessRepository` |
| `DELETE /documents/files/{fileID}/access/device` | Same |
| `POST /documents/files/{fileID}/share` | Writes to project's `ShareRepository` |
| `DELETE /documents/files/{fileID}/share` | Same |
| `GET /devices/{deviceModelID}/documents` | Device-scoped listing; filter logic is project-specific |
| `POST /documents/files` | Override-only — project sets compound access records at creation time |
| `GET /documents/files/{fileID}` | Override-only — project enriches with access and share data |
| `PATCH /documents/files/{fileID}` | Override-only — project updates company access alongside metadata |
