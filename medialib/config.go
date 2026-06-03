package medialib

// Tables holds the (dynamic) table names the library reads and writes. The
// deletion trail defaults to "{media objects table}_deletions".
type Tables struct {
	Media                 string
	MediaObjects          string
	MediaObjectsDeletions string
}

// NewDefaultTables returns the conventional table names: "media",
// "media_objects" and "media_objects_deletions".
func NewDefaultTables() Tables {
	return Tables{
		Media:                 "media",
		MediaObjects:          "media_objects",
		MediaObjectsDeletions: "media_objects_deletions",
	}
}
