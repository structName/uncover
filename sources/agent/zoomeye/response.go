package zoomeye

type ZoomEyeResponse struct {
	Total   int             `json:"total"`
	Results []ZoomEyeResult `json:"data"`
}

type ZoomEyeResult struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	URL      string `json:"url"`
	Title    string `json:"title"`
	App      string `json:"app"`
	Service  string `json:"service"`
	Banner   string `json:"banner"`
	OS       string `json:"os"`
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
	Version  string `json:"version"`
}
