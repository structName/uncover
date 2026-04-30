package quake

type quakeService struct {
	Name   string            `json:"name"`
	Banner string            `json:"banner"`
	HTTP   *quakeServiceHTTP `json:"http,omitempty"`
}

type quakeServiceHTTP struct {
	Title      string `json:"title"`
	StatusCode int    `json:"status_code"`
}

type quakeLocation struct {
	CountryCN  string `json:"country_cn"`
	ProvinceCN string `json:"province_cn"`
	CityCN     string `json:"city_cn"`
}

type quakeComponent struct {
	ProductName string `json:"product_name"`
	Version     string `json:"version"`
}

type responseData struct {
	Hostname   string           `json:"hostname"`
	IP         string           `json:"ip"`
	Port       int              `json:"port"`
	Service    *quakeService    `json:"service,omitempty"`
	Location   *quakeLocation   `json:"location,omitempty"`
	Components []quakeComponent `json:"components,omitempty"`
}

type pagination struct {
	Count     int `json:"count"`
	PageIndex int `json:"page_index"`
	PageSize  int `json:"page_size"`
	Total     int `json:"total"`
}

type meta struct {
	Pagination pagination `json:"pagination"`
}

type Response struct {
	Data    []responseData `json:"data"`
	Message string         `json:"message"`
	Meta    meta           `json:"meta"`
}
