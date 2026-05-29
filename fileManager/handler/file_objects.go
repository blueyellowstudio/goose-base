package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/blueyellowstudio/goose-base/fileManager"
	"github.com/blueyellowstudio/goose-base/fileManager/domain"
	"github.com/blueyellowstudio/goose-base/fileManager/handler/dto"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (h *Handler) createFileObject(w http.ResponseWriter, r *http.Request) {
	fileID, err := uuid.Parse(chi.URLParam(r, "fileID"))
	if err != nil {
		http.Error(w, "invalid file id", http.StatusBadRequest)
		return
	}

	var req dto.CreateFileObjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	obj := domain.FileObject{
		FileID:           fileID,
		Name:             req.Name,
		OriginalFileName: req.OriginalFileName,
		LanguageID:       req.LanguageID,
		Metadata:         []byte("{}"),
	}

	result, err := h.service.CreateFileObject(r.Context(), obj)
	if err != nil {
		http.Error(w, "failed to create file object", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) updateFileObject(w http.ResponseWriter, r *http.Request) {
	objectID, err := uuid.Parse(chi.URLParam(r, "objectID"))
	if err != nil {
		http.Error(w, "invalid object id", http.StatusBadRequest)
		return
	}

	var req dto.UpdateFileObjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	existing, err := h.service.GetFileObject(r.Context(), objectID)
	if err != nil {
		http.Error(w, "failed to get file object", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "file object not found", http.StatusNotFound)
		return
	}

	existing.Name = req.Name
	existing.LanguageID = req.LanguageID
	if req.OriginalFileName != nil {
		existing.OriginalFileName = *req.OriginalFileName
	}

	if err := h.service.UpdateFileObject(r.Context(), *existing); err != nil {
		http.Error(w, "failed to update file object", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) softDeleteFileObject(w http.ResponseWriter, r *http.Request) {
	objectID, err := uuid.Parse(chi.URLParam(r, "objectID"))
	if err != nil {
		http.Error(w, "invalid object id", http.StatusBadRequest)
		return
	}

	if err := h.service.SoftDeleteFileObject(r.Context(), objectID); err != nil {
		http.Error(w, "failed to delete file object", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getUploadURL(w http.ResponseWriter, r *http.Request) {
	objectID, err := uuid.Parse(chi.URLParam(r, "objectID"))
	if err != nil {
		http.Error(w, "invalid object id", http.StatusBadRequest)
		return
	}

	url, storedFileID, err := h.service.GenerateUploadLink(r.Context(), objectID)
	if err != nil {
		http.Error(w, "failed to generate upload url", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto.URLResponse{URL: url, StoredFileID: storedFileID})
}

func (h *Handler) activateStoredFile(w http.ResponseWriter, r *http.Request) {
	storedFileID, err := uuid.Parse(chi.URLParam(r, "storedFileID"))
	if err != nil {
		http.Error(w, "invalid stored file id", http.StatusBadRequest)
		return
	}

	if err := h.service.ActivateStoredFile(r.Context(), storedFileID); err != nil {
		if errors.Is(err, fileManager.ErrStoredFileNotFound) {
			http.Error(w, "stored file not found", http.StatusNotFound)
		} else {
			http.Error(w, "failed to activate stored file", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
