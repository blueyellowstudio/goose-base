package handler

import (
	"net/http"

	"github.com/blueyellowstudio/goose-base/fileManager"
)

// HandlerOverrides allows the consuming project to replace specific handlers with
// project-specific implementations. If a field is nil, no route is registered for
// that endpoint — the project must register it separately if needed.
type HandlerOverrides struct {
	CreateFile http.HandlerFunc
	GetFile    http.HandlerFunc
	UpdateFile http.HandlerFunc
}

// Handler provides HTTP handlers for the fileManager service.
type Handler struct {
	service   *fileManager.Service
	overrides HandlerOverrides
}

// NewHandler creates a Handler wrapping the given service.
// Pass HandlerOverrides to inject project-specific logic for CreateFile, GetFile, and UpdateFile.
func NewHandler(service *fileManager.Service, overrides HandlerOverrides) *Handler {
	return &Handler{
		service:   service,
		overrides: overrides,
	}
}
