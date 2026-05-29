package handler

import "github.com/go-chi/chi/v5"

// Routers holds three separate chi routers reflecting the access level required per endpoint.
// In projects where read and write share the same access level, the same router can be passed
// for multiple fields.
type Routers struct {
	Read   chi.Router // GET endpoints
	Create chi.Router // POST endpoints
	Update chi.Router // PATCH/PUT/DELETE endpoints
}

// RegisterRoutes registers all fileManager HTTP routes on the provided routers.
// Override handlers (CreateFile, GetFile, UpdateFile) are registered only when non-nil.
func (h *Handler) RegisterRoutes(r Routers) {
	// Folders
	r.Create.Post("/documents/folders", h.createFolder)
	r.Update.Patch("/documents/folders/{folderID}", h.renameFolder)
	r.Update.Delete("/documents/folders/{folderID}", h.softDeleteFolder)
	r.Update.Post("/documents/folders/{folderID}/move", h.moveFolder)
	r.Read.Get("/documents/folders/{folderID}/ancestors", h.getFolderBreadcrumbs)

	// Files — overridable
	if h.overrides.CreateFile != nil {
		r.Create.Post("/documents/files", h.overrides.CreateFile)
	}
	if h.overrides.GetFile != nil {
		r.Read.Get("/documents/files/{fileID}", h.overrides.GetFile)
	}
	if h.overrides.UpdateFile != nil {
		r.Update.Patch("/documents/files/{fileID}", h.overrides.UpdateFile)
	}
	r.Update.Delete("/documents/files/{fileID}", h.softDeleteFile)
	r.Update.Post("/documents/files/{fileID}/move", h.moveFile)

	// File objects
	r.Create.Post("/documents/files/{fileID}/objects", h.createFileObject)
	r.Update.Put("/documents/files/{fileID}/objects/{objectID}", h.updateFileObject)
	r.Update.Delete("/documents/files/{fileID}/objects/{objectID}", h.softDeleteFileObject)
	r.Read.Get("/documents/files/{fileID}/objects/{objectID}/upload-url", h.getUploadURL)
	r.Update.Post("/documents/files/{fileID}/objects/{objectID}/stored-files/{storedFileID}/activate", h.activateStoredFile)
}
