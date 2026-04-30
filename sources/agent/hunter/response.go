package hunter

type ResponseDataArr struct {
	IP         string            `json:"ip"`
	Port       int               `json:"port"`
	Domain     string            `json:"domain"`
	WebTitle   string            `json:"web_title"`
	Component  []HunterComponent `json:"component"`
	Banner     string            `json:"banner"`
	Country    string            `json:"country"`
	Province   string            `json:"province"`
	City       string            `json:"city"`
	Protocol   string            `json:"protocol"`
	OS         string            `json:"os"`
	StatusCode int               `json:"status_code"`
	URL        string            `json:"url"`
}

type HunterComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type responseData struct {
	Total        int               `json:"total"`
	Time         int               `json:"time"`
	Arr          []ResponseDataArr `json:"arr"`
	ConsumeQuota string            `json:"consume_quota"`
	RestQuota    string            `json:"rest_quota"`
}

type Response struct {
	Code int          `json:"code"`
	Data responseData `json:"data"`
	Msg  string       `json:"msg"`
}
