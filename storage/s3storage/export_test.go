package s3storage

// SetListPageSize sets the page size of ListObjects and the chunk size of DeleteObjects.
func SetListPageSize(s *Storage, size int32) { s.listPageSize = size }
