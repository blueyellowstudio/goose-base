package handler

import (
	"encoding/json"
	"net/http"

	"github.com/blueyellowstudio/goose-base/fileManager/handler/dto"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (h *Handler) softDeleteFile(w http.ResponseWriter, r *http.Request) {
	fileID, err := uuid.Parse(chi.URLParam(r, "fileID"))
	if err != nil {
		http.Error(w, "invalid file id", http.StatusBadRequest)
		return
	}

	if err := h.service.SoftDeleteFile(r.Context(), fileID); err != nil {
		http.Error(w, "failed to delete file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) moveFile(w http.ResponseWriter, r *http.Request) {
	fileID, err := uuid.Parse(chi.URLParam(r, "fileID"))
	if err != nil {
		http.Error(w, "invalid file id", http.StatusBadRequest)
		return
	}

	var req dto.MoveFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.MoveFile(r.Context(), fileID, req.NewFolderID); err != nil {
		http.Error(w, "failed to move file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
