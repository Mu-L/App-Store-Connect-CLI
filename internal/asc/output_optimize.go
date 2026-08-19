package asc

// KeywordRankRow is one keyword's position in the public App Store search
// result window. Rank is null whenever the app is absent from that window.
type KeywordRankRow struct {
	Keyword      string `json:"keyword"`
	Rank         *int   `json:"rank"`
	TotalResults *int   `json:"totalResults,omitempty"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
}

// KeywordRankSummary counts keyword outcomes by status.
type KeywordRankSummary struct {
	Keywords    int `json:"keywords"`
	Ranked      int `json:"ranked"`
	Absent      int `json:"absent"`
	Unavailable int `json:"unavailable"`
}

// KeywordRankReport is the stable JSON contract emitted by keyword rank
// evaluation.
type KeywordRankReport struct {
	SchemaVersion string             `json:"schemaVersion"`
	GeneratedAt   string             `json:"generatedAt,omitempty"`
	AppID         string             `json:"appId"`
	Country       string             `json:"country"`
	Platform      string             `json:"platform"`
	Workers       int                `json:"workers"`
	Summary       KeywordRankSummary `json:"summary"`
	Rows          []KeywordRankRow   `json:"rows"`
}
