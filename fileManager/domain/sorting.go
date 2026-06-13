package domain

type SortBy struct {
	Keyword string
	DESC    bool
}

func NewSortByList(sortBy ...SortBy) []SortBy {
	return sortBy
}

func NewSortBySingle(keyword string) []SortBy {
	return []SortBy{SortBy{Keyword: keyword}}
}

func NewSortBySingleDesc(keyword string) []SortBy {
	return []SortBy{SortBy{Keyword: keyword, DESC: true}}
}

func NoSorting() []SortBy {
	return []SortBy{}
}