package quake

type Request struct {
	Query       string   `json:"query"`
	Size        int      `json:"size"`
	Start       int      `json:"start"`
	IgnoreCache bool     `json:"ignore_cache"`
	Latest      bool     `json:"latest"`
	StartTime   string   `json:"start_time,omitempty"`
	EndTime     string   `json:"end_time,omitempty"`
	Include     []string `json:"include"`
}
