package handler

import (
	"encoding/json"
	"net/http"

	"github.com/blueyellowstudio/goose-base/fileManager/domain"
	"github.com/blueyellowstudio/goose-base/fileManager/handler/dto"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (h *Handler) createFolder(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	userID, ok := userIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	folder := domain.Folder{
		ParentID:  req.ParentID,
		Name:      req.Name,
		CreatedBy: userID,
		Metadata:  []byte("{}"),
	}

	result, err := h.service.CreateFolder(r.Context(), folder)
	if err != nil {
		http.Error(w, "failed to create folder", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) renameFolder(w http.ResponseWriter, r *http.Request) {
	folderID, err := uuid.Parse(chi.URLParam(r, "folderID"))
	if err != nil {
		http.Error(w, "invalid folder id", http.StatusBadRequest)
		return
	}

	var req dto.RenameFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	folder := domain.Folder{ID: folderID, Name: req.Name, Metadata: []byte("{}")}
	if err := h.service.RenameFolder(r.Context(), folder); err != nil {
		http.Error(w, "failed to rename folder", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) softDeleteFolder(w http.ResponseWriter, r *http.Request) {
	folderID, err := uuid.Parse(chi.URLParam(r, "folderID"))
	if err != nil {
		http.Error(w, "invalid folder id", http.StatusBadRequest)
		return
	}

	if err := h.service.SoftDeleteFolder(r.Context(), folderID); err != nil {
		http.Error(w, "failed to delete folder", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getFolderBreadcrumbs(w http.ResponseWriter, r *http.Request) {
	folderID, err := uuid.Parse(chi.URLParam(r, "folderID"))
	if err != nil {
		http.Error(w, "invalid folder id", http.StatusBadRequest)
		return
	}

	folders, err := h.service.GetFolderBreadcrumbs(r.Context(), folderID)
	if err != nil {
		http.Error(w, "failed to get breadcrumbs", http.StatusInternalServerError)
		return
	}

	breadcrumbs := make([]dto.BreadcrumbItem, len(folders))
	for i, f := range folders {
		breadcrumbs[i] = dto.BreadcrumbItem{ID: f.ID, Name: f.Name}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(breadcrumbs)
}

func (h *Handler) moveFolder(w http.ResponseWriter, r *http.Request) {
	folderID, err := uuid.Parse(chi.URLParam(r, "folderID"))
	if err != nil {
		http.Error(w, "invalid folder id", http.StatusBadRequest)
		return
	}

	var req dto.MoveFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.MoveFolder(r.Context(), folderID, req.NewParentID); err != nil {
		http.Error(w, "failed to move folder: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
