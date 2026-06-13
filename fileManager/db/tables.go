package db

type FileManagerTables struct {
	Files        string
	FileObjects  string
	Folders      string
	StoredFiles  string
	DeletedItems string
}

func NewDefaultFileManagerTables() FileManagerTables {
	return FileManagerTables{
		Files:        "files",
		FileObjects:  "file_objects",
		Folders:      "folders",
		StoredFiles:  "stored_files",
		DeletedItems: "deleted_items",
	}
}
