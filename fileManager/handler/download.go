package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/blueyellowstudio/goose-base/fileManager"
	"github.com/blueyellowstudio/goose-base/fileManager/handler/dto"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// FileAccessChecker reports whether the incoming request may access the given file.
// Returns (allowed, httpStatusCode, error). statusCode is only meaningful on denial.
type FileAccessChecker func(r *http.Request, fileID uuid.UUID) (bool, int, error)

// DownloadHandler provides public file download handlers backed by a FileAccessChecker.
type DownloadHandler struct {
	service     *fileManager.Service
	checkAccess FileAccessChecker
}

// NewDownloadHandler creates a DownloadHandler. checkAccess is called on every request
// to determine whether the caller is allowed to access the target file.
func NewDownloadHandler(service *fileManager.Service, checkAccess FileAccessChecker) *DownloadHandler {
	return &DownloadHandler{service: service, checkAccess: checkAccess}
}

// RegisterDownloadRoutes registers the three download endpoints.
// publicRouter receives GetFileDownloadMeta and GetFileDownloadURL (optional/no auth).
// authRouter receives GetDownloadURL (requires authenticated user).
func (h *DownloadHandler) RegisterDownloadRoutes(publicRouter, authRouter chi.Router) {
	publicRouter.Get("/documents/files/{fileID}/downloadMeta", h.GetFileDownloadMeta)
	publicRouter.Get("/documents/files/{fileID}/getUrl", h.GetFileDownloadURL)
	authRouter.Get("/documents/files/{fileID}/objects/{objectID}/download-url", h.GetDownloadURL)
}

// GetFileDownloadMeta returns file-level metadata for the best matching language variant.
func (h *DownloadHandler) GetFileDownloadMeta(w http.ResponseWriter, r *http.Request) {
	fileID, languageID, ok := h.resolveFileDownloadAccess(w, r)
	if !ok {
		return
	}

	meta, err := h.service.GetFileDownloadMeta(r.Context(), fileID, languageID)
	if err != nil {
		if isFileDownloadNotFound(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load file download metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

// GetFileDownloadURL returns a signed download URL for the best matching language variant.
func (h *DownloadHandler) GetFileDownloadURL(w http.ResponseWriter, r *http.Request) {
	fileID, languageID, ok := h.resolveFileDownloadAccess(w, r)
	if !ok {
		return
	}

	download, err := strconv.ParseBool(r.URL.Query().Get("download"))
	if err != nil {
		download = false
	}

	url, err := h.service.GetFileDownloadURL(r.Context(), fileID, languageID, download)
	if err != nil {
		if isFileDownloadNotFound(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to generate file download url", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto.URLResponse{URL: url})
}

// GetDownloadURL returns a signed download URL for a specific file object (language variant).
func (h *DownloadHandler) GetDownloadURL(w http.ResponseWriter, r *http.Request) {
	objectID, err := uuid.Parse(chi.URLParam(r, "objectID"))
	if err != nil {
		http.Error(w, "invalid object id", http.StatusBadRequest)
		return
	}

	download, err := strconv.ParseBool(r.URL.Query().Get("download"))
	if err != nil {
		download = false
	}

	fileObj, err := h.service.GetFileObject(r.Context(), objectID)
	if err != nil {
		http.Error(w, "failed to get file object", http.StatusInternalServerError)
		return
	}

	allowed, statusCode, err := h.checkAccess(r, fileObj.FileID)
	if err != nil || !allowed {
		http.Error(w, "Not allowed to access file", statusCode)
		return
	}

	url, err := h.service.GenerateDownloadLink(r.Context(), objectID, download)
	if err != nil {
		if errors.Is(err, fileManager.ErrFileObjectNotFound) || errors.Is(err, fileManager.ErrStoredFileNotFound) {
			http.Error(w, "file object not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to generate download url", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto.URLResponse{URL: url})
}

// resolveFileDownloadAccess validates auth, parses fileID and optional languageId,
// and checks access. Writes the error response and returns ok=false on any failure.
func (h *DownloadHandler) resolveFileDownloadAccess(w http.ResponseWriter, r *http.Request) (fileID uuid.UUID, languageID *int, ok bool) {
	fileID, err := uuid.Parse(chi.URLParam(r, "fileID"))
	if err != nil {
		http.Error(w, "invalid file id", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}

	languageID, err = parseOptionalLanguageID(r)
	if err != nil {
		http.Error(w, "invalid language id", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}

	allowed, statusCode, err := h.checkAccess(r, fileID)
	if err != nil || !allowed {
		http.Error(w, "Not allowed to access file", statusCode)
		return uuid.Nil, nil, false
	}

	return fileID, languageID, true
}

func parseOptionalLanguageID(r *http.Request) (*int, error) {
	value := r.URL.Query().Get("languageId")
	if value == "" {
		return nil, nil
	}
	languageID, err := strconv.Atoi(value)
	if err != nil {
		return nil, err
	}
	return &languageID, nil
}

func isFileDownloadNotFound(err error) bool {
	return errors.Is(err, fileManager.ErrFileNotFound) ||
		errors.Is(err, fileManager.ErrFileObjectNotFound) ||
		errors.Is(err, fileManager.ErrStoredFileNotFound)
}

