package medialib

import (
	"testing"

	"github.com/google/uuid"
)

func TestObjectPath(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	cases := []struct {
		name       string
		storageKey string
		ext        string
		want       string
	}{
		{"with ext", "sk", "jpg", "sk/11111111-1111-1111-1111-111111111111/original.jpg"},
		{"leading dot ext", "sk", ".mp4", "sk/11111111-1111-1111-1111-111111111111/original.mp4"},
		{"no ext", "sk", "", "sk/11111111-1111-1111-1111-111111111111/original"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ObjectPath(tc.storageKey, id, tc.ext); got != tc.want {
				t.Fatalf("ObjectPath = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildURL(t *testing.T) {
	b := NewURLBuilder("https://proj.supabase.co/storage/v1/", "media", nil)
	path := "sk/obj/original.jpg"

	img := b.BuildURL("image", path)
	wantImg := "https://proj.supabase.co/storage/v1/render/image/authenticated/media/sk/obj/original.jpg"
	if img != wantImg {
		t.Fatalf("image url = %q, want %q", img, wantImg)
	}

	vid := b.BuildURL("video", path)
	wantVid := "https://proj.supabase.co/storage/v1/object/authenticated/media/sk/obj/original.jpg"
	if vid != wantVid {
		t.Fatalf("video url = %q, want %q", vid, wantVid)
	}
}

func TestBuildURLCustomImageTypes(t *testing.T) {
	b := NewURLBuilder("https://proj.supabase.co/storage/v1", "media", []string{"photo"})
	if got := b.BuildURL("photo", "p"); got != "https://proj.supabase.co/storage/v1/render/image/authenticated/media/p" {
		t.Fatalf("custom image type not rendered: %q", got)
	}
	if got := b.BuildURL("image", "p"); got != "https://proj.supabase.co/storage/v1/object/authenticated/media/p" {
		t.Fatalf("non-listed type should be plain object: %q", got)
	}
}
