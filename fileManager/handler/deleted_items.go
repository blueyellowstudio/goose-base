package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/blueyellowstudio/goose-base/fileManager/handler/dto"
)

// listDeletedItems returns deletion tombstones for files and file objects soft-deleted
// after the "since" query parameter (required, RFC3339 timestamp).
func (h *Handler) listDeletedItems(w http.ResponseWriter, r *http.Request) {
	sinceParam := r.URL.Query().Get("since")
	if sinceParam == "" {
		http.Error(w, "since query parameter is required", http.StatusBadRequest)
		return
	}

	since, err := time.Parse(time.RFC3339, sinceParam)
	if err != nil {
		http.Error(w, "invalid since timestamp, expected RFC3339", http.StatusBadRequest)
		return
	}

	items, err := h.service.ListDeletedItemsSince(r.Context(), since)
	if err != nil {
		http.Error(w, "failed to list deleted items", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto.DeletedItemsResponse{Items: items})
}
