package netlas

import (
	"fmt"
	"net/url"
	"strings"
)

type Request struct {
	Query string `json:"query"`
	Start int    `json:"start"`
}

func (r *Request) buildURL(baseURL string) string {
	baseURL = strings.TrimRight(baseURL, "/") + "/"
	return baseURL +
		baseEndpoint +
		"?q=" +
		url.QueryEscape(r.Query) +
		"&start=" +
		fmt.Sprint(r.Start)
}
