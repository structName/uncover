package hunter

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d&is_web=%d&start_time=%s&end_time=%s"
)

var (
	// Size is Hunter's API maximum per-page ceiling. Kept exported for
	// backwards compatibility; the Query loop derives the actual per-page
	// size from query.Limit via sources.ClampPageSize.
	Size       = 100
	StatusCode = ""
	PortFilter = false
	IsWeb      = 0
	StartTime  = ""
	EndTime    = ""
)

type Agent struct{}

// joinHunterComponentNames flattens Hunter's [{name, version}] array to
// "nginx, apache" — names only, comma-separated, version dropped (still
// available via RawData for callers that need it).
func joinHunterComponentNames(comps []HunterComponent) string {
	if len(comps) == 0 {
		return ""
	}
	names := make([]string, 0, len(comps))
	for _, c := range comps {
		if name := strings.TrimSpace(c.Name); name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

func (agent *Agent) Name() string {
	return "hunter"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.HunterToken == "" {
		return nil, errors.New("empty hunter keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0
		page := 1
		pageSize := sources.ClampPageSize(query.Limit, Size)
		for {
			hunterRequest := &Request{
				ApiKey:     session.Keys.HunterToken,
				Search:     query.Query,
				Page:       page,
				PageSize:   pageSize,
				StatusCode: StatusCode,
				PortFilter: PortFilter,
				IsWeb:      IsWeb,
				StartTime:  StartTime,
				EndTime:    EndTime,
			}
			hunterResponse := agent.query(session.ResolveURL(agent.Name(), URL), session, hunterRequest, results)

			if hunterResponse == nil {
				break
			}

			numberOfResults += len(hunterResponse.Data.Arr)
			page++

			if numberOfResults >= query.Limit || hunterResponse.Data.Total == 0 || len(hunterResponse.Data.Arr) == 0 {
				break
			}

		}
	}()

	return results, nil
}

func (agent *Agent) query(URL string, session *sources.Session, hunterRequest *Request, results chan sources.Result) *Response {
	resp, err := agent.queryURL(session, URL, hunterRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	hunterResponse := &Response{}
	respBodyBytes, readErr := io.ReadAll(resp.Body)
	defer func() {
		if bodyCloseErr := resp.Body.Close(); bodyCloseErr != nil {
			gologger.Info().Msgf("response body close error : %v", bodyCloseErr)
		}
	}()
	if readErr != nil {
		results <- sources.Result{Source: agent.Name(), Error: readErr}
		return nil
	}
	if err := json.Unmarshal(respBodyBytes, hunterResponse); err != nil {
		result := sources.Result{Source: agent.Name(), Error: err}
		result.Raw = respBodyBytes
		results <- result
		return nil
	}
	if hunterResponse.Code == http.StatusOK && hunterResponse.Data.Total > 0 {
		for _, hunterResult := range hunterResponse.Data.Arr {
			result := sources.Result{Source: agent.Name()}
			result.IP = hunterResult.IP
			result.Port = hunterResult.Port
			result.Host = hunterResult.Domain
			result.Url = hunterResult.URL

			extras := map[string]string{}
			if hunterResult.WebTitle != "" {
				extras["web_title"] = hunterResult.WebTitle
			}
			if hunterResult.Banner != "" {
				extras["banner"] = hunterResult.Banner
			}
			if hunterResult.Country != "" {
				extras["country"] = hunterResult.Country
			}
			if hunterResult.Province != "" {
				extras["province"] = hunterResult.Province
			}
			if hunterResult.City != "" {
				extras["city"] = hunterResult.City
			}
			if hunterResult.Protocol != "" {
				extras["protocol"] = hunterResult.Protocol
			}
			if hunterResult.StatusCode > 0 {
				extras["status_code"] = strconv.Itoa(hunterResult.StatusCode)
			}
			if name := joinHunterComponentNames(hunterResult.Component); name != "" {
				extras["component"] = name
			}
			if len(extras) > 0 {
				result.Extras = extras
			}

			raw, _ := json.Marshal(hunterResult)
			result.Raw = raw
			results <- result
		}
	}

	return hunterResponse
}

func (agent *Agent) queryURL(session *sources.Session, URL string, hunterRequest *Request) (*http.Response, error) {
	base64Query := base64.URLEncoding.EncodeToString([]byte(hunterRequest.Search))
	hunterURL := fmt.Sprintf(URL, hunterRequest.ApiKey, base64Query, hunterRequest.Page, hunterRequest.PageSize, hunterRequest.IsWeb, hunterRequest.StartTime, hunterRequest.EndTime)
	request, err := sources.NewHTTPRequest(http.MethodGet, hunterURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	return session.Do(request, agent.Name())
}
