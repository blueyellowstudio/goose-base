package domain

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// Cursor encodes the position of the last item on a page, used for keyset pagination.
// Items are ordered by (name ASC, id ASC).
// Short JSON keys ("n", "i") are intentional to keep the base64-encoded cursor string compact.
type Cursor struct {
	Name string    `json:"n"`
	ID   uuid.UUID `json:"i"`
}

// Encode serialises the cursor to a URL-safe base64 string.
func (c Cursor) Encode() string {
	b, _ := json.Marshal(c)
	return base64.URLEncoding.EncodeToString(b)
}

// DecodeCursor parses a cursor string produced by Cursor.Encode.
func DecodeCursor(s string) (*Cursor, error) {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode cursor: %w", err)
	}
	var c Cursor
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("decode cursor: %w", err)
	}
	return &c, nil
}
