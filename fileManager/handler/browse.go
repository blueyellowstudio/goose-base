package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/blueyellowstudio/goose-base/fileManager"
	"github.com/blueyellowstudio/goose-base/fileManager/domain"
	"github.com/blueyellowstudio/goose-base/fileManager/handler/dto"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const defaultBrowsePageLimit = 50
const maxBrowsePageLimit = 200

// FolderAccessResolver resolves the access filter for a browse request.
// The project extracts any URL params it needs (e.g. companyID) directly from r.
// Returns (filter, 0, nil) on success, or (nil, statusCode, err) on auth/permission failure.
type FolderAccessResolver func(r *http.Request) (domain.AccessFilter, int, error)

// FileEnricher transforms raw files into JSON before encoding the browse response.
// Pass nil to encode []domain.FileWithObject directly.
type FileEnricher func(ctx context.Context, files []domain.FileWithObject) (json.RawMessage, error)

// BrowseHandler provides handlers for browsing folder contents with pluggable access control.
type BrowseHandler struct {
	service       *fileManager.Service
	resolveAccess FolderAccessResolver
	enrichFiles   FileEnricher // nil = encode raw []domain.FileWithObject
}

// NewBrowseHandler creates a BrowseHandler. resolveAccess is called on every request to
// derive the access filter. enrichFiles may be nil.
func NewBrowseHandler(service *fileManager.Service, resolveAccess FolderAccessResolver, enrichFiles FileEnricher) *BrowseHandler {
	return &BrowseHandler{service: service, resolveAccess: resolveAccess, enrichFiles: enrichFiles}
}

// RegisterBrowseRoutes registers BrowseDocuments, ListFolderContents, and
// ListFolderFiles on the provided router. Mount the router under a project-specific
// prefix (e.g. /companies/{companyID}) before calling this.
func (h *BrowseHandler) RegisterBrowseRoutes(r chi.Router) {
	r.Get("/documents", h.BrowseDocuments)
	r.Get("/documents/folders/{folderID}", h.ListFolderContents)
	r.Get("/documents/folders/{folderID}/files", h.ListFolderFiles)
}

// BrowseDocuments returns a page of root-level folders and files visible to the user.
func (h *BrowseHandler) BrowseDocuments(w http.ResponseWriter, r *http.Request) {
	h.listFolderContentsHandler(w, r, nil)
}

// ListFolderContents returns a page of immediate children (folders + files) of a folder.
func (h *BrowseHandler) ListFolderContents(w http.ResponseWriter, r *http.Request) {
	folderID, err := uuid.Parse(chi.URLParam(r, "folderID"))
	if err != nil {
		http.Error(w, "invalid folder id", http.StatusBadRequest)
		return
	}
	h.listFolderContentsHandler(w, r, &folderID)
}

// ListFolderFiles returns a page of files in a folder without subfolder entries.
func (h *BrowseHandler) ListFolderFiles(w http.ResponseWriter, r *http.Request) {
	folderID, err := uuid.Parse(chi.URLParam(r, "folderID"))
	if err != nil {
		http.Error(w, "invalid folder id", http.StatusBadRequest)
		return
	}

	filter, statusCode, err := h.resolveAccess(r)
	if err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	limit, _, fileCursor, badParam := parseBrowsePaginationParams(r)
	if badParam != "" {
		http.Error(w, "invalid "+badParam, http.StatusBadRequest)
		return
	}

	nameSearch := r.URL.Query().Get("search")
	var nameSearchPtr *string
	if nameSearch != "" {
		nameSearchPtr = &nameSearch
	}

	files, err := h.service.GetFolderFilesPaged(r.Context(), &folderID, filter, fileCursor, limit, nameSearchPtr)
	if err != nil {
		slog.Error("failed to list folder files", "error", err)
		http.Error(w, "failed to list folder files", http.StatusInternalServerError)
		return
	}

	files, fileNext := nextBrowseFileCursor(files, limit)

	filesJSON, err := h.marshalFiles(r.Context(), files)
	if err != nil {
		http.Error(w, "failed to encode files", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto.FolderFilesResponse{
		Files:          filesJSON,
		FileNextCursor: fileNext,
	})
}

func (h *BrowseHandler) listFolderContentsHandler(w http.ResponseWriter, r *http.Request, parentID *uuid.UUID) {
	filter, statusCode, err := h.resolveAccess(r)
	if err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	limit, folderCursor, fileCursor, badParam := parseBrowsePaginationParams(r)
	if badParam != "" {
		http.Error(w, "invalid "+badParam, http.StatusBadRequest)
		return
	}

	nameSearch := r.URL.Query().Get("search")
	var nameSearchPtr *string
	if nameSearch != "" {
		nameSearchPtr = &nameSearch
	}

	folders, files, err := h.service.GetFolderContentsPaged(r.Context(), parentID, filter, folderCursor, fileCursor, limit, nameSearchPtr)
	if err != nil {
		slog.Error("failed to list folder contents", "error", err)
		http.Error(w, "failed to list folder contents", http.StatusInternalServerError)
		return
	}

	folders, folderNext := nextBrowseFolderCursor(folders, limit)
	files, fileNext := nextBrowseFileCursor(files, limit)

	filesJSON, err := h.marshalFiles(r.Context(), files)
	if err != nil {
		http.Error(w, "failed to encode files", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto.FolderContentsResponse{
		Folders:          folders,
		FolderNextCursor: folderNext,
		Files:            filesJSON,
		FileNextCursor:   fileNext,
	})
}

// marshalFiles runs the optional FileEnricher, or marshals files as-is.
func (h *BrowseHandler) marshalFiles(ctx context.Context, files []domain.FileWithObject) (json.RawMessage, error) {
	if h.enrichFiles != nil {
		return h.enrichFiles(ctx, files)
	}
	return json.Marshal(files)
}

func parseBrowsePaginationParams(r *http.Request) (limit int, folderCursor *domain.Cursor, fileCursor *domain.Cursor, badParam string) {
	limit = defaultBrowsePageLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxBrowsePageLimit {
		limit = maxBrowsePageLimit
	}

	if v := r.URL.Query().Get("folderCursor"); v != "" {
		c, err := domain.DecodeCursor(v)
		if err != nil {
			return 0, nil, nil, "folderCursor"
		}
		folderCursor = c
	}
	if v := r.URL.Query().Get("fileCursor"); v != "" {
		c, err := domain.DecodeCursor(v)
		if err != nil {
			return 0, nil, nil, "fileCursor"
		}
		fileCursor = c
	}
	return
}

func nextBrowseFolderCursor(folders []domain.Folder, limit int) ([]domain.Folder, *string) {
	if len(folders) <= limit {
		return folders, nil
	}
	last := folders[limit-1]
	c := domain.Cursor{Name: last.Name, ID: last.ID}.Encode()
	return folders[:limit], &c
}

func nextBrowseFileCursor(files []domain.FileWithObject, limit int) ([]domain.FileWithObject, *string) {
	if len(files) <= limit {
		return files, nil
	}
	last := files[limit-1].File
	c := domain.Cursor{Name: last.Name, ID: last.ID}.Encode()
	return files[:limit], &c
}
