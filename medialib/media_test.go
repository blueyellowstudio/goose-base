package medialib

import (
	"context"
	"testing"
	"time"

	domain "github.com/blueyellowstudio/goose-base/medialib/domain"
	"github.com/blueyellowstudio/goose-base/storage"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
)

// --- fakes ---

type fakeRunner struct{}

func (fakeRunner) RunInTx(ctx context.Context, fn func(ctx context.Context, tx txpkg.Transaction) error) error {
	return fn(ctx, txpkg.Wrap("test-tx"))
}

type fakeMediaRepo struct {
	items   map[uuid.UUID]domain.Media
	objects *fakeObjectRepo // for ListWithActiveObjectByIDs joins; wired in newTestService
}

func newFakeMediaRepo() *fakeMediaRepo { return &fakeMediaRepo{items: map[uuid.UUID]domain.Media{}} }

func (r *fakeMediaRepo) Create(_ context.Context, _ txpkg.Transaction, m domain.Media) (*domain.Media, error) {
	m.CreatedAt = time.Now()
	m.UpdatedAt = m.CreatedAt
	r.items[m.ID] = m
	out := m
	return &out, nil
}
func (r *fakeMediaRepo) Update(_ context.Context, _ txpkg.Transaction, m domain.Media) error {
	r.items[m.ID] = m
	return nil
}
func (r *fakeMediaRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Media, error) {
	m, ok := r.items[id]
	if !ok {
		return nil, nil
	}
	out := m
	return &out, nil
}
func (r *fakeMediaRepo) GetByIDTx(ctx context.Context, _ txpkg.Transaction, id uuid.UUID) (*domain.Media, error) {
	return r.GetByID(ctx, id)
}
func (r *fakeMediaRepo) ListWithActiveObjectByIDs(ctx context.Context, ids []uuid.UUID) ([]domain.MediaWithActiveObject, error) {
	out := []domain.MediaWithActiveObject{}
	for _, id := range ids {
		m, ok := r.items[id]
		if !ok {
			continue
		}
		entry := domain.MediaWithActiveObject{Media: m}
		if r.objects != nil {
			if obj, _ := r.objects.GetActiveByMediaID(ctx, id); obj != nil {
				entry.Object = obj
			}
		}
		out = append(out, entry)
	}
	return out, nil
}
func (r *fakeMediaRepo) SoftDelete(_ context.Context, _ txpkg.Transaction, id uuid.UUID, t time.Time) error {
	m := r.items[id]
	m.DeletedAt = &t
	r.items[id] = m
	return nil
}
func (r *fakeMediaRepo) HardDelete(_ context.Context, _ txpkg.Transaction, id uuid.UUID) error {
	delete(r.items, id)
	return nil
}

type fakeObjectRepo struct{ items map[uuid.UUID]domain.MediaObject }

func newFakeObjectRepo() *fakeObjectRepo { return &fakeObjectRepo{items: map[uuid.UUID]domain.MediaObject{}} }

func (r *fakeObjectRepo) Create(_ context.Context, _ txpkg.Transaction, o domain.MediaObject) (*domain.MediaObject, error) {
	o.CreatedAt = time.Now()
	o.UpdatedAt = o.CreatedAt
	r.items[o.ID] = o
	out := o
	return &out, nil
}
func (r *fakeObjectRepo) Update(_ context.Context, _ txpkg.Transaction, o domain.MediaObject) error {
	r.items[o.ID] = o
	return nil
}
func (r *fakeObjectRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.MediaObject, error) {
	o, ok := r.items[id]
	if !ok {
		return nil, nil
	}
	out := o
	return &out, nil
}
func (r *fakeObjectRepo) GetActiveByMediaID(_ context.Context, mediaID uuid.UUID) (*domain.MediaObject, error) {
	for _, o := range r.items {
		if o.MediaID == mediaID && o.Status == domain.MediaObjectStatusActive && o.DeletedAt == nil {
			out := o
			return &out, nil
		}
	}
	return nil, nil
}
func (r *fakeObjectRepo) ListByMediaID(_ context.Context, mediaID uuid.UUID) ([]domain.MediaObject, error) {
	out := []domain.MediaObject{}
	for _, o := range r.items {
		if o.MediaID == mediaID {
			out = append(out, o)
		}
	}
	return out, nil
}
func (r *fakeObjectRepo) SupersedeActiveByMediaID(_ context.Context, _ txpkg.Transaction, mediaID uuid.UUID) (bool, error) {
	affected := false
	now := time.Now()
	for id, o := range r.items {
		if o.MediaID == mediaID && o.Status == domain.MediaObjectStatusActive && o.DeletedAt == nil {
			o.Status = domain.MediaObjectStatusDeleted
			o.DeletedAt = &now
			r.items[id] = o
			affected = true
		}
	}
	return affected, nil
}
func (r *fakeObjectRepo) HardDelete(_ context.Context, _ txpkg.Transaction, id uuid.UUID) error {
	delete(r.items, id)
	return nil
}

func (r *fakeObjectRepo) countActive(mediaID uuid.UUID) int {
	n := 0
	for _, o := range r.items {
		if o.MediaID == mediaID && o.Status == domain.MediaObjectStatusActive && o.DeletedAt == nil {
			n++
		}
	}
	return n
}

type fakeDeletionRepo struct{ items []domain.MediaObjectDeletion }

func (r *fakeDeletionRepo) Create(_ context.Context, _ txpkg.Transaction, d domain.MediaObjectDeletion) (*domain.MediaObjectDeletion, error) {
	d.ID = uuid.New()
	d.DeletedAt = time.Now()
	r.items = append(r.items, d)
	out := d
	return &out, nil
}
func (r *fakeDeletionRepo) ListSince(_ context.Context, since time.Time) ([]domain.MediaObjectDeletion, error) {
	out := []domain.MediaObjectDeletion{}
	for _, d := range r.items {
		if d.DeletedAt.After(since) {
			out = append(out, d)
		}
	}
	return out, nil
}

type fakeStorage struct {
	exists  bool
	size    int64
	deleted []string
}

func (f *fakeStorage) GenerateUploadURL(bucket, objectKey string, _ *string) (*storage.UploadInfo, error) {
	return &storage.UploadInfo{URL: "upload://" + bucket + "/" + objectKey, ObjectKey: objectKey, Bucket: bucket}, nil
}
func (f *fakeStorage) GenerateDownloadURL(_, _, _ string, _ bool) (*storage.DownloadInfo, error) {
	return &storage.DownloadInfo{}, nil
}
func (f *fakeStorage) DeleteObject(_, objectKey string) error {
	f.deleted = append(f.deleted, objectKey)
	return nil
}
func (f *fakeStorage) DeleteObjects(_ string, objectKeys []string) error {
	f.deleted = append(f.deleted, objectKeys...)
	return nil
}
func (f *fakeStorage) ListObjects(_, _ string) ([]string, error) { return nil, nil }
func (f *fakeStorage) GetObjectInfo(_, _ string) (*storage.ObjectInfo, error) {
	return &storage.ObjectInfo{Size: f.size}, nil
}
func (f *fakeStorage) FileExists(_, _ string) bool { return f.exists }

func newTestService(store storage.Storage) (*Service, *fakeMediaRepo, *fakeObjectRepo, *fakeDeletionRepo) {
	mr := newFakeMediaRepo()
	or := newFakeObjectRepo()
	mr.objects = or
	dr := &fakeDeletionRepo{}
	svc := NewService(
		fakeRunner{}, mr, or, dr, store,
		NewURLBuilder("https://proj.supabase.co/storage/v1", "media", nil),
		"media", nil,
	)
	return svc, mr, or, dr
}

// --- tests ---

func TestCreateMediaDefaultsStorageKeyToID(t *testing.T) {
	svc, _, _, _ := newTestService(&fakeStorage{})
	m, err := svc.CreateMedia(context.Background(), "", "image")
	if err != nil {
		t.Fatal(err)
	}
	if m.StorageKey != m.ID.String() {
		t.Fatalf("storage key = %q, want %q", m.StorageKey, m.ID.String())
	}
}

func TestActivateSupersedesPriorActive(t *testing.T) {
	ctx := context.Background()
	store := &fakeStorage{exists: true, size: 4242}
	svc, _, or, _ := newTestService(store)

	m, err := svc.CreateMedia(ctx, "", "image")
	if err != nil {
		t.Fatal(err)
	}

	_, obj1, err := svc.CreateMediaObject(ctx, m.ID, "image/jpeg", "jpg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ActivateMediaObject(ctx, obj1.ID, 1); err != nil {
		t.Fatal(err)
	}

	// Real size from storage should overwrite the client-sent value.
	active, _ := or.GetByID(ctx, obj1.ID)
	if active.SizeBytes == nil || *active.SizeBytes != 4242 {
		t.Fatalf("size not overwritten with actual: %v", active.SizeBytes)
	}

	_, obj2, err := svc.CreateMediaObject(ctx, m.ID, "image/jpeg", "jpg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ActivateMediaObject(ctx, obj2.ID, 1); err != nil {
		t.Fatal(err)
	}

	if got := or.countActive(m.ID); got != 1 {
		t.Fatalf("active object count = %d, want 1", got)
	}
	cur, err := svc.GetActiveURL(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantURL := "https://proj.supabase.co/storage/v1/render/image/authenticated/media/" + m.StorageKey + "/" + obj2.ID.String() + "/original.jpg"
	if cur != wantURL {
		t.Fatalf("active url = %q, want %q", cur, wantURL)
	}

	old, _ := or.GetByID(ctx, obj1.ID)
	if old.Status != domain.MediaObjectStatusDeleted || old.DeletedAt == nil {
		t.Fatalf("prior active not superseded: status=%s deletedAt=%v", old.Status, old.DeletedAt)
	}
}

func TestResolveActiveURLs(t *testing.T) {
	ctx := context.Background()
	store := &fakeStorage{exists: true, size: 7}
	svc, _, _, _ := newTestService(store)

	// media A: image with an active object.
	a, _ := svc.CreateMedia(ctx, "", "image")
	_, objA, _ := svc.CreateMediaObject(ctx, a.ID, "image/jpeg", "jpg", nil)
	if err := svc.ActivateMediaObject(ctx, objA.ID, 1); err != nil {
		t.Fatal(err)
	}

	// media B: created but no active object yet.
	b, _ := svc.CreateMedia(ctx, "", "video")

	missing := uuid.New()

	// Duplicate a.ID to confirm dedupe doesn't break the result.
	res, err := svc.ResolveActiveURLs(ctx, []uuid.UUID{a.ID, b.ID, missing, a.ID})
	if err != nil {
		t.Fatal(err)
	}

	ra, ok := res[a.ID]
	if !ok || !ra.HasActive {
		t.Fatalf("media A: expected resolved active object, got %+v (ok=%v)", ra, ok)
	}
	wantURL := "https://proj.supabase.co/storage/v1/render/image/authenticated/media/" + a.StorageKey + "/" + objA.ID.String() + "/original.jpg"
	if ra.URL != wantURL {
		t.Fatalf("media A url = %q, want %q", ra.URL, wantURL)
	}
	if ra.Type != "image" {
		t.Fatalf("media A type = %q, want image", ra.Type)
	}

	rb, ok := res[b.ID]
	if !ok {
		t.Fatal("media B: expected present in result")
	}
	if rb.HasActive || rb.URL != "" {
		t.Fatalf("media B: expected no active object, got %+v", rb)
	}
	if rb.Type != "video" {
		t.Fatalf("media B type = %q, want video", rb.Type)
	}

	if _, ok := res[missing]; ok {
		t.Fatal("missing media id should be absent from result")
	}
}

func TestActivateRejectsMissingUpload(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newTestService(&fakeStorage{exists: false})

	m, _ := svc.CreateMedia(ctx, "", "image")
	_, obj, _ := svc.CreateMediaObject(ctx, m.ID, "image/jpeg", "jpg", nil)

	if err := svc.ActivateMediaObject(ctx, obj.ID, 1); err != ErrObjectNotUploaded {
		t.Fatalf("err = %v, want ErrObjectNotUploaded", err)
	}
}

func TestHardDeleteMediaObjectWritesTrail(t *testing.T) {
	ctx := context.Background()
	store := &fakeStorage{exists: true, size: 10}
	svc, _, _, dr := newTestService(store)

	m, _ := svc.CreateMedia(ctx, "", "image")
	_, obj, _ := svc.CreateMediaObject(ctx, m.ID, "image/jpeg", "jpg", nil)

	if err := svc.HardDeleteMediaObject(ctx, obj.ID); err != nil {
		t.Fatal(err)
	}
	if len(store.deleted) != 1 {
		t.Fatalf("storage deletes = %d, want 1", len(store.deleted))
	}
	since := time.Now().Add(-time.Minute)
	trail, _ := svc.GetDeletionsSince(ctx, since)
	if len(trail) != 1 || trail[0].MediaObjectID != obj.ID {
		t.Fatalf("deletion trail not written: %+v", trail)
	}
	if len(dr.items) != 1 {
		t.Fatalf("deletion repo entries = %d, want 1", len(dr.items))
	}
}
