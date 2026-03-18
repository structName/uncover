package publicwww

import (
	"net/url"
	"strings"
)

type Request struct {
	Query string `json:"query"`
	Start int    `json:"start"`
}

func (r *Request) buildURL(baseURL, key string) string {
	baseURL = strings.TrimRight(baseURL, "/") + "/"
	return baseURL +
		baseEndpoint +
		url.QueryEscape(`"`+r.Query+`"`) +
		`/?export=urls&key=` + key
}
