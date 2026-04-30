package shodan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"errors"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://api.shodan.io/shodan/host/search?key=%s&query=%s&page=%d"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "shodan"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.Shodan == "" {
		return nil, errors.New("empty shodan keys")
	}
	results := make(chan sources.Result)

	go func() {
		defer close(results)

		currentPage := 1
		var numberOfResults, totalResults int
		for {
			shodanRequest := &ShodanRequest{
				Query: query.Query,
				Page:  currentPage,
			}

			shodanResponse := agent.query(session.ResolveURL(agent.Name(), URL), session, shodanRequest, results)

			if shodanResponse == nil {
				break
			}
			currentPage++
			numberOfResults += len(shodanResponse.Results)
			if totalResults == 0 {
				totalResults = shodanResponse.Total
			}

			// query certificates
			if numberOfResults > query.Limit || numberOfResults > totalResults || len(shodanResponse.Results) == 0 {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, shodanRequest *ShodanRequest) (*http.Response, error) {
	shodanURL := fmt.Sprintf(URL, session.Keys.Shodan, url.QueryEscape(shodanRequest.Query), shodanRequest.Page)
	request, err := sources.NewHTTPRequest(http.MethodGet, shodanURL, nil)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, shodanRequest *ShodanRequest, results chan sources.Result) *ShodanResponse {
	// query certificates
	resp, err := agent.queryURL(session, URL, shodanRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	shodanResponse := &ShodanResponse{}
	if err := json.NewDecoder(resp.Body).Decode(shodanResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	for _, shodanResult := range shodanResponse.Results {
		result := sources.Result{Source: agent.Name()}
		if port, ok := shodanResult["port"].(float64); ok {
			result.Port = int(port)
		}
		if ip, ok := shodanResult["ip_str"].(string); ok {
			result.IP = ip
		}
		if hostnames, ok := shodanResult["hostnames"].([]interface{}); ok {
			for _, hostname := range hostnames {
				result.Host = fmt.Sprint(hostname)
			}
		}

		extras := map[string]string{}
		if v, ok := shodanResult["transport"].(string); ok && v != "" {
			extras["transport"] = v
		}
		if v, ok := shodanResult["product"].(string); ok && v != "" {
			extras["product"] = v
		}
		if v, ok := shodanResult["data"].(string); ok && v != "" {
			extras["data"] = v
		}
		if http, ok := shodanResult["http"].(map[string]interface{}); ok {
			if v, ok := http["title"].(string); ok && v != "" {
				extras["http.title"] = v
			}
			if v, ok := http["server"].(string); ok && v != "" {
				extras["http.server"] = v
			}
			if v, ok := http["status"].(float64); ok {
				extras["http.status"] = strconv.Itoa(int(v))
			}
		}
		if loc, ok := shodanResult["location"].(map[string]interface{}); ok {
			for _, k := range []string{"country_name", "country_code", "region_code", "city"} {
				if v, ok := loc[k].(string); ok && v != "" {
					extras[k] = v
				}
			}
		}
		if len(extras) > 0 {
			result.Extras = extras
		}

		raw, _ := json.Marshal(shodanResult)
		result.Raw = raw
		results <- result
	}

	return shodanResponse
}

type ShodanRequest struct {
	Query string
	Page  int
}
