# File Manager — HTTP Handler

The `fileManager/handler` package provides ready-made HTTP handlers that wire directly onto the `fileManager.Service`. It covers the standard CRUD operations for folders, files, and file objects — including the upload/activate lifecycle. Endpoints that require project-specific access logic (e.g. download URL gating, access control records) are intentionally left out and must be registered by the consuming project.

---

## Package overview

```
fileManager/handler/
├── context.go        # UserID context key + InjectUserIDMiddleware
├── handler.go        # Handler struct + HandlerOverrides
├── routes.go         # Routers struct + RegisterRoutes
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

---

## Registered routes

| Router | Method | Path |
|--------|--------|------|
| Create | POST | `/documents/folders` |
| Update | PATCH | `/documents/folders/{folderID}` |
| Update | DELETE | `/documents/folders/{folderID}` |
| Update | POST | `/documents/folders/{folderID}/move` |
| Read | GET | `/documents/folders/{folderID}/ancestors` |
| Create | POST | `/documents/files` *(override only)* |
| Read | GET | `/documents/files/{fileID}` *(override only)* |
| Update | PATCH | `/documents/files/{fileID}` *(override only)* |
| Update | DELETE | `/documents/files/{fileID}` |
| Update | POST | `/documents/files/{fileID}/move` |
| Create | POST | `/documents/files/{fileID}/objects` |
| Update | PUT | `/documents/files/{fileID}/objects/{objectID}` |
| Update | DELETE | `/documents/files/{fileID}/objects/{objectID}` |
| Read | GET | `/documents/files/{fileID}/objects/{objectID}/upload-url` |
| Update | POST | `/documents/files/{fileID}/objects/{objectID}/stored-files/{storedFileID}/activate` |

Routes marked *override only* are registered only when the corresponding `HandlerOverrides` field is non-nil.

---

## Usage example

The example below shows a project that uses an `authRouter` / `elevatedRouter` split. Both routers receive the `UserIDMiddleware`. `CreateFile`, `GetFile`, and `UpdateFile` carry project-specific access-record logic and are provided as overrides.

```go
package document

import (
    "encoding/json"
    "net/http"

    "myproject/internal/authorization"
    "myproject/internal/db/documents"

    "github.com/blueyellowstudio/goose-base/fileManager"
    fmhandler "github.com/blueyellowstudio/goose-base/fileManager/handler"
    "github.com/blueyellowstudio/goose-base/fileManager/domain"
    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
    "golang.org/x/sync/errgroup"
)

// Handler extends the library handler with project-specific repos.
type Handler struct {
    service    *fileManager.Service
    accessRepo *documents.AccessRepository
    shareRepo  *documents.ShareRepository
    lib        *fmhandler.Handler
}

func NewHandler(
    service *fileManager.Service,
    accessRepo *documents.AccessRepository,
    shareRepo  *documents.ShareRepository,
) *Handler {
    h := &Handler{
        service:    service,
        accessRepo: accessRepo,
        shareRepo:  shareRepo,
    }
    h.lib = fmhandler.NewHandler(service, fmhandler.HandlerOverrides{
        CreateFile: h.CreateFile,
        GetFile:    h.GetFile,
        UpdateFile: h.UpdateFile,
    })
    return h
}

// LibHandler returns the embedded library handler for route registration.
func (h *Handler) LibHandler() *fmhandler.Handler {
    return h.lib
}

// UserIDMiddleware bridges the project's auth claims into the library's context key.
func (h *Handler) UserIDMiddleware(next http.Handler) http.Handler {
    return fmhandler.InjectUserIDMiddleware(func(r *http.Request) (uuid.UUID, bool) {
        claims := authorization.GetUserClaims(r.Context())
        if claims == nil {
            return uuid.UUID{}, false
        }
        return claims.UserID, true
    })(next)
}

// CreateFile creates a file and optionally sets company / device access in the same request.
func (h *Handler) CreateFile(w http.ResponseWriter, r *http.Request) {
    var req struct {
        FolderID      *uuid.UUID `json:"folderId,omitempty"`
        Name          string     `json:"name"`
        FileType      *string    `json:"fileType,omitempty"`
        Category      int        `json:"category"`
        CompanyLevel  *uuid.UUID `json:"companyLevel,omitempty"`
        DeviceModelID *int       `json:"deviceModelId,omitempty"`
        UserLevel     *int16     `json:"userLevel,omitempty"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request body", http.StatusBadRequest)
        return
    }
    if req.Name == "" {
        http.Error(w, "name is required", http.StatusBadRequest)
        return
    }

    claims := authorization.GetUserClaims(r.Context())
    if claims == nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    file := domain.File{
        FolderID: req.FolderID,
        Name:     req.Name,
        UserID:   claims.UserID,
        FileType: req.FileType,
        Category: req.Category,
        Metadata: []byte("{}"),
    }
    result, err := h.service.CreateFile(r.Context(), file)
    if err != nil {
        http.Error(w, "failed to create file", http.StatusInternalServerError)
        return
    }

    if req.CompanyLevel != nil {
        if err := h.accessRepo.SetCompanyAccess(r.Context(), nil, documents.CompanyDocumentAccess{
            DocumentID:   result.ID,
            CompanyLevel: *req.CompanyLevel,
            CreatedBy:    claims.UserID,
        }); err != nil {
            http.Error(w, "failed to set company access", http.StatusInternalServerError)
            return
        }
    }
    if req.DeviceModelID != nil && req.UserLevel != nil {
        if err := h.accessRepo.SetDeviceAccess(r.Context(), nil, documents.DeviceDocumentAccess{
            DocumentID:    result.ID,
            DeviceModelID: *req.DeviceModelID,
            UserLevel:     *req.UserLevel,
            CreatedBy:     claims.UserID,
        }); err != nil {
            http.Error(w, "failed to set device access", http.StatusInternalServerError)
            return
        }
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(result)
}

// GetFile returns file metadata enriched with objects, access records, and share link.
func (h *Handler) GetFile(w http.ResponseWriter, r *http.Request) {
    fileID, err := uuid.Parse(chi.URLParam(r, "fileID"))
    if err != nil {
        http.Error(w, "invalid file id", http.StatusBadRequest)
        return
    }

    file, err := h.service.GetFile(r.Context(), fileID)
    if err != nil {
        http.Error(w, "failed to get file", http.StatusInternalServerError)
        return
    }
    if file == nil {
        http.Error(w, "file not found", http.StatusNotFound)
        return
    }

    includeAll := r.URL.Query().Get("includeUnavailable") == "true"

    var (
        fileObjects   []domain.FileObject
        companyAccess *documents.CompanyDocumentAccess
        deviceAccess  []documents.DeviceDocumentAccess
        fileShare     *documents.FileShare
    )
    g, gctx := errgroup.WithContext(r.Context())
    g.Go(func() error {
        var err error
        if includeAll {
            fileObjects, err = h.service.ListFileObjects(gctx, fileID)
        } else {
            fileObjects, err = h.service.GetAvailableFileObjects(gctx, fileID)
        }
        return err
    })
    g.Go(func() error {
        var err error
        companyAccess, err = h.accessRepo.GetCompanyAccess(gctx, fileID)
        return err
    })
    g.Go(func() error {
        var err error
        deviceAccess, err = h.accessRepo.ListDeviceAccess(gctx, fileID)
        return err
    })
    g.Go(func() error {
        var err error
        fileShare, err = h.shareRepo.GetByFileId(gctx, fileID)
        return err
    })
    if err := g.Wait(); err != nil {
        http.Error(w, "failed to load file metadata", http.StatusInternalServerError)
        return
    }

    type response struct {
        File          domain.File                      `json:"file"`
        FileObjects   []domain.FileObject              `json:"fileObjects"`
        CompanyAccess *documents.CompanyDocumentAccess `json:"companyAccess,omitempty"`
        DeviceAccess  []documents.DeviceDocumentAccess `json:"deviceAccess"`
        ShareLink     *string                          `json:"shareLink,omitempty"`
    }

    var shareLink *string
    if fileShare != nil {
        link := buildShareLink(fileShare.Id, fileShare.Key)
        shareLink = &link
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response{
        File:          *file,
        FileObjects:   fileObjects,
        CompanyAccess: companyAccess,
        DeviceAccess:  deviceAccess,
        ShareLink:     shareLink,
    })
}

// UpdateFile updates file metadata and optionally refreshes the company access level.
func (h *Handler) UpdateFile(w http.ResponseWriter, r *http.Request) {
    claims := authorization.GetUserClaims(r.Context())
    if claims == nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    fileID, err := uuid.Parse(chi.URLParam(r, "fileID"))
    if err != nil {
        http.Error(w, "invalid file id", http.StatusBadRequest)
        return
    }

    var req struct {
        Name         string     `json:"name"`
        FileType     *string    `json:"fileType,omitempty"`
        Category     *int       `json:"category,omitempty"`
        CompanyLevel *uuid.UUID `json:"companyLevel,omitempty"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request body", http.StatusBadRequest)
        return
    }
    if req.Name == "" {
        http.Error(w, "name is required", http.StatusBadRequest)
        return
    }

    existing, err := h.service.GetFile(r.Context(), fileID)
    if err != nil {
        http.Error(w, "failed to get file", http.StatusInternalServerError)
        return
    }
    if existing == nil {
        http.Error(w, "file not found", http.StatusNotFound)
        return
    }

    existing.Name = req.Name
    if req.FileType != nil {
        existing.FileType = req.FileType
    }
    if req.Category != nil {
        existing.Category = *req.Category
    }

    if err := h.service.UpdateFile(r.Context(), *existing); err != nil {
        http.Error(w, "failed to update file", http.StatusInternalServerError)
        return
    }

    if req.CompanyLevel != nil {
        if err := h.accessRepo.SetCompanyAccess(r.Context(), nil, documents.CompanyDocumentAccess{
            DocumentID:   fileID,
            CompanyLevel: *req.CompanyLevel,
            CreatedBy:    claims.UserID,
        }); err != nil {
            http.Error(w, "failed to set company access", http.StatusInternalServerError)
            return
        }
    }

    w.WriteHeader(http.StatusNoContent)
}
```

### Route registration (routes.go)

```go
docHandler := document.NewHandler(service, accessRepo, shareRepo)

elevatedWithFm := elevatedRouter.With(docHandler.UserIDMiddleware)
authWithFm     := authRouter.With(docHandler.UserIDMiddleware)

docHandler.LibHandler().RegisterRoutes(fmhandler.Routers{
    Read:   authWithFm,
    Create: elevatedWithFm,
    Update: elevatedWithFm,
})

// Project-specific routes registered separately
r.With(authMaybe).Get("/documents/files/{fileID}/downloadMeta", docHandler.GetFileDownloadMeta)
r.With(authMaybe).Get("/documents/files/{fileID}/getUrl",       docHandler.GetFileDownloadURL)
authRouter.Get("/documents/files/{fileID}/objects/{objectID}/download-url", docHandler.GetDownloadURL)
```

---

## What stays in the project

The following endpoints are intentionally omitted from the library because they rely on project-specific access repositories or business logic:

| Endpoint | Reason |
|----------|--------|
| `GET /documents/files/{fileID}/downloadMeta` | Validates access via project `accessRepo` before resolving the download metadata |
| `GET /documents/files/{fileID}/getUrl` | Same — resolves per-user or public access before generating the URL |
| `GET /documents/files/{fileID}/objects/{objectID}/download-url` | Calls `isRequestAllowedToAccessFile` which checks elevated permissions, public availability, and per-user device/company access |
| `POST /documents/files/{fileID}/access/device` | Writes to project's `AccessRepository` |
| `DELETE /documents/files/{fileID}/access/device` | Same |
| `POST /documents/files/{fileID}/share` | Writes to project's `ShareRepository` |
| `DELETE /documents/files/{fileID}/share` | Same |
| Browse / listing routes | Require project-specific pagination, permission middleware, and access enrichment |
