package medialib

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// URLBuilder constructs read URLs for media objects. Reads are not signed by the
// library — Supabase RLS gates them and the client attaches its JWT. Image types
// get a render/transform-capable URL (the app appends ?width=<n>); other types
// get the plain object URL.
type URLBuilder struct {
	storageBaseURL string // e.g. https://<proj>.supabase.co/storage/v1
	bucket         string
	imageTypes     map[string]bool
}

// NewURLBuilder builds read URLs against the given Supabase storage base URL and
// bucket. imageTypes lists media.type values that resolve to render-capable
// (resizable) URLs; when nil it defaults to {"image"}.
func NewURLBuilder(storageBaseURL, bucket string, imageTypes []string) *URLBuilder {
	if imageTypes == nil {
		imageTypes = []string{"image"}
	}
	set := make(map[string]bool, len(imageTypes))
	for _, t := range imageTypes {
		set[t] = true
	}
	return &URLBuilder{
		storageBaseURL: strings.TrimSuffix(storageBaseURL, "/"),
		bucket:         bucket,
		imageTypes:     set,
	}
}

// ObjectPath returns the storage path for a media object:
// "{storageKey}/{objectID}/original.{ext}". ext may be supplied with or without
// a leading dot.
func ObjectPath(storageKey string, objectID uuid.UUID, ext string) string {
	ext = strings.TrimPrefix(ext, ".")
	if ext == "" {
		return fmt.Sprintf("%s/%s/original", storageKey, objectID.String())
	}
	return fmt.Sprintf("%s/%s/original.%s", storageKey, objectID.String(), ext)
}

// BuildURL returns the fully-built read URL for the object at path with the
// given media type. Image types get the render endpoint (no param ⇒ original,
// ?width=<n> appended by the app ⇒ resized); other types (e.g. video) get the
// plain object endpoint.
func (b *URLBuilder) BuildURL(mediaType, path string) string {
	if b.imageTypes[mediaType] {
		return fmt.Sprintf("%s/render/image/authenticated/%s/%s", b.storageBaseURL, b.bucket, path)
	}
	return fmt.Sprintf("%s/object/authenticated/%s/%s", b.storageBaseURL, b.bucket, path)
}
