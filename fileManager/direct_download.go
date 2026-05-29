package fileManager

import (
	"context"
	"fmt"
	"mime"
	"strings"
	"time"

	fileaccess "github.com/blueyellowstudio/goose-base/fileManager/directFileAccess"
	"github.com/blueyellowstudio/goose-base/fileManager/domain"

	"github.com/google/uuid"
)

var _ fileaccess.DirectFileAccess = (*Service)(nil)

// GetFileDownloadMeta returns file-level download metadata for the resolved language variant.
func (s *Service) GetFileDownloadMeta(ctx context.Context, fileID uuid.UUID, languageID *int) (fileaccess.FileDownloadMeta, error) {
	file, fileObject, err := s.resolveFileAndObjectForDownload(ctx, fileID, languageID)
	if err != nil {
		return fileaccess.FileDownloadMeta{}, err
	}

	storedFile, err := s.getLatestActiveStoredFile(ctx, fileObject.ID)
	if err != nil {
		return fileaccess.FileDownloadMeta{}, err
	}

	baseName, extension := getDownloadNameParts(file, fileObject)

	return fileaccess.FileDownloadMeta{
		FileType:      file.FileType,
		FileSize:      storedFile.FileSize,
		FileUpdatedAt: storedFile.CreatedAt,
		MetaUpdatedAt: laterTime(file.UpdatedAt, fileObject.UpdatedAt),
		Name:          baseName,
		FileExtension: extension,
		LanguageID:    fileObject.LanguageID,
	}, nil
}

// GetFileDownloadURL returns a pre-signed download URL for the resolved language variant.
func (s *Service) GetFileDownloadURL(ctx context.Context, fileID uuid.UUID, languageID *int, download bool) (string, error) {
	file, fileObject, err := s.resolveFileAndObjectForDownload(ctx, fileID, languageID)
	if err != nil {
		return "", err
	}

	return s.createDownloadLinkForResolvedFile(ctx, fileObject, file, download)
}

func (s *Service) resolveFileAndObjectForDownload(ctx context.Context, fileID uuid.UUID, languageID *int) (*domain.File, *domain.FileObject, error) {
	file, err := s.files.GetByID(ctx, fileID)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve file download target: %w", err)
	}
	if file == nil {
		return nil, nil, ErrFileNotFound
	}

	fileObject, err := s.resolveFileObjectForDownload(ctx, fileID, languageID)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve file download target: %w", err)
	}
	if fileObject == nil {
		return nil, nil, ErrFileObjectNotFound
	}

	return file, fileObject, nil
}

func (s *Service) resolveFileObjectForDownload(ctx context.Context, fileID uuid.UUID, languageID *int) (*domain.FileObject, error) {
	if languageID != nil {
		fileObject, err := s.objects.GetByFileAndLanguage(ctx, fileID, *languageID)
		if err != nil {
			return nil, err
		}
		if fileObject != nil {
			return fileObject, nil
		}
	}

	return s.objects.GetDefaultByFile(ctx, fileID)
}

func (s *Service) createDownloadLinkForResolvedFile(ctx context.Context, fileObject *domain.FileObject, file *domain.File, download bool) (string, error) {
	storedFile, err := s.getLatestActiveStoredFile(ctx, fileObject.ID)
	if err != nil {
		return "", err
	}

	filename := buildDownloadFilename(file, fileObject)
	url, err := s.domainCbs.CreateDownloadLinkForFile(ctx, storedFile.ID, filename, download)
	if err != nil {
		return "", fmt.Errorf("create download link: %w", err)
	}
	return url, nil
}

func (s *Service) getLatestActiveStoredFile(ctx context.Context, fileObjectID uuid.UUID) (*domain.StoredFile, error) {
	storedFile, err := s.storedFiles.GetLatestActive(ctx, fileObjectID)
	if err != nil {
		return nil, fmt.Errorf("get latest active stored file: %w", err)
	}
	if storedFile == nil {
		return nil, ErrStoredFileNotFound
	}
	return storedFile, nil
}

// buildDownloadFilename returns the resolved download name including its file extension.
func buildDownloadFilename(file *domain.File, fileObj *domain.FileObject) string {
	baseName, extension := getDownloadNameParts(file, fileObj)
	return baseName + extension
}

func getDownloadNameParts(file *domain.File, fileObj *domain.FileObject) (string, string) {
	name := strings.TrimSpace(file.Name)
	if strings.TrimSpace(fileObj.Name) != "" {
		name = strings.TrimSpace(fileObj.Name)
	}

	extension := getFileExtension(file.FileType)
	if extension == "" {
		return name, ""
	}

	if strings.HasSuffix(strings.ToLower(name), strings.ToLower(extension)) {
		return name[:len(name)-len(extension)], extension
	}

	return name, extension
}

func getFileExtension(fileType *string) string {
	if fileType == nil {
		return ""
	}

	mediaType := strings.TrimSpace(*fileType)
	if mediaType == "" {
		return ""
	}

	if parsedMediaType, _, parseErr := mime.ParseMediaType(mediaType); parseErr == nil {
		mediaType = parsedMediaType
	}

	extensions, err := mime.ExtensionsByType(mediaType)
	if err != nil || len(extensions) == 0 {
		return ""
	}

	return extensions[0]
}

func laterTime(first time.Time, second time.Time) time.Time {
	if second.After(first) {
		return second
	}
	return first
}
