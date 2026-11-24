package fileManager

import (
	"context"
	"errors"
	"testing"

	"github.com/blueyellowstudio/goose-base/fileManager/domain"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateFileWithRunsAfterCreateInTheFileTransaction(t *testing.T) {
	runner := &recordingRunner{}
	service := newCreateFileTestService(runner)
	var afterCreateTx txpkg.Transaction
	var afterCreateFile domain.File

	created, err := service.CreateFileWith(t.Context(), domain.File{Name: "manual.pdf"},
		func(_ context.Context, tx txpkg.Transaction, file domain.File) error {
			afterCreateTx = tx
			afterCreateFile = file
			return nil
		})

	require.NoError(t, err)
	assert.Equal(t, runner.tx, afterCreateTx)
	assert.Equal(t, *created, afterCreateFile)
	assert.Equal(t, 1, runner.commitCount)
}

func TestCreateFileWithRollsBackWhenAfterCreateFails(t *testing.T) {
	runner := &recordingRunner{}
	service := newCreateFileTestService(runner)
	afterCreateErr := errors.New("access write failed")

	created, err := service.CreateFileWith(t.Context(), domain.File{Name: "manual.pdf"},
		func(context.Context, txpkg.Transaction, domain.File) error { return afterCreateErr })

	require.ErrorIs(t, err, afterCreateErr)
	assert.Nil(t, created)
	assert.Zero(t, runner.commitCount)
}

func TestCreateFileWithAcceptsNoAfterCreate(t *testing.T) {
	runner := &recordingRunner{}
	service := newCreateFileTestService(runner)

	created, err := service.CreateFileWith(t.Context(), domain.File{Name: "manual.pdf"}, nil)

	require.NoError(t, err)
	assert.Equal(t, "manual.pdf", created.Name)
	assert.Equal(t, 1, runner.commitCount)
}

func newCreateFileTestService(runner *recordingRunner) *Service {
	return NewService(runner, fakeFileRepository{}, nil, nil, nil, nil, nil, noOpDBCallbacks{}, nil)
}

// recordingRunner counts a transaction as committed only when fn succeeds, like a real runner.
type recordingRunner struct {
	tx          txpkg.Transaction
	commitCount int
}

func (r *recordingRunner) RunInTx(ctx context.Context, fn func(context.Context, txpkg.Transaction) error) error {
	r.tx = txpkg.Wrap("test-tx")
	if err := fn(ctx, r.tx); err != nil {
		return err
	}
	r.commitCount++
	return nil
}

type fakeFileRepository struct {
	domain.FileRepository
}

func (fakeFileRepository) Create(_ context.Context, _ txpkg.Transaction, file domain.File) (*domain.File, error) {
	file.ID = uuid.New()
	return &file, nil
}

type noOpDBCallbacks struct{}

func (noOpDBCallbacks) FileAdded(context.Context, txpkg.Transaction, domain.File) error { return nil }

func (noOpDBCallbacks) FileDeleted(context.Context, txpkg.Transaction, domain.File) error {
	return nil
}

func (noOpDBCallbacks) StoredFileDeleted(context.Context, txpkg.Transaction, domain.StoredFile) error {
	return nil
}
