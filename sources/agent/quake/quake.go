package quake

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/projectdiscovery/uncover/sources"
	errorutil "github.com/projectdiscovery/utils/errors"
)

const (
	URL = "https://quake.360.net/api/v3/search/quake_service"
	// Size is Quake's API maximum per-page ceiling. The Query loop
	// derives the actual per-page size from query.Limit via
	// sources.ClampPageSize.
	Size = 100
)

var (
	IgnoreCache = true
	Latest      = true
	StartTime   = ""
	EndTime     = ""
	Include = []string{
		"ip", "port", "hostname",
		"service.name",
		"service.banner",
		"service.http.title",
		"service.http.status_code",
		"location.country_cn",
		"location.province_cn",
		"location.city_cn",
		"components",
	}
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "quake"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.QuakeToken == "" {
		return nil, errors.New("empty quake keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0
		pageSize := sources.ClampPageSize(query.Limit, Size)

		for {
			quakeRequest := &Request{
				Query:       query.Query,
				Size:        pageSize,
				Start:       numberOfResults,
				IgnoreCache: IgnoreCache,
				Latest:      Latest,
				StartTime:   StartTime,
				EndTime:     EndTime,
				Include:     Include,
			}
			quakeResponse := agent.query(session.ResolveURL(agent.Name(), URL), session, quakeRequest, results)

			if quakeResponse == nil {
				break
			}

			if len(quakeResponse.Data) == 0 {
				break
			}

			numberOfResults += len(quakeResponse.Data)

			// Stop after consuming this page if we've reached the requested
			// limit or exhausted the upstream total. Increment-then-check
			// (with >=) avoids the prior off-by-one where an extra page was
			// always fetched after the limit had been reached.
			if numberOfResults >= query.Limit {
				break
			}
			if quakeResponse.Meta.Pagination.Count > 0 && numberOfResults >= quakeResponse.Meta.Pagination.Total {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) query(URL string, session *sources.Session, quakeRequest *Request, results chan sources.Result) *Response {
	resp, err := agent.queryURL(session, URL, quakeRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	quakeResponse := &Response{}
	respdata, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf("%v: %v", err, string(respdata))}
		return nil
	}
	if err := json.NewDecoder(bytes.NewReader(respdata)).Decode(quakeResponse); err != nil {
		errx := errorutil.NewWithErr(err)
		// quake has different json format for error messages try to unmarshal it in map and print map
		var errMap map[string]interface{}
		if err := json.NewDecoder(bytes.NewReader(respdata)).Decode(&errMap); err == nil {
			errx = errx.Msgf("failed to decode quake response: %v", errMap)
		} else {
			errx = errx.Msgf("failed to decode quake response: %s", string(respdata))
		}
		results <- sources.Result{Source: agent.Name(), Error: errx}
		return nil
	}

	for _, qr := range quakeResponse.Data {
		result := sources.Result{Source: agent.Name()}
		result.IP = qr.IP
		result.Port = qr.Port
		result.Host = qr.Hostname

		extras := map[string]string{}
		if qr.Service != nil {
			if qr.Service.Name != "" {
				extras["service.name"] = qr.Service.Name
			}
			if qr.Service.Banner != "" {
				extras["service.banner"] = qr.Service.Banner
			}
			if qr.Service.HTTP != nil {
				if qr.Service.HTTP.Title != "" {
					extras["service.http.title"] = qr.Service.HTTP.Title
				}
				if qr.Service.HTTP.StatusCode > 0 {
					extras["service.http.status_code"] = strconv.Itoa(qr.Service.HTTP.StatusCode)
				}
			}
		}
		if qr.Location != nil {
			if qr.Location.CountryCN != "" {
				extras["location.country_cn"] = qr.Location.CountryCN
			}
			if qr.Location.ProvinceCN != "" {
				extras["location.province_cn"] = qr.Location.ProvinceCN
			}
			if qr.Location.CityCN != "" {
				extras["location.city_cn"] = qr.Location.CityCN
			}
		}
		if len(qr.Components) > 0 {
			if name := strings.TrimSpace(qr.Components[0].ProductName); name != "" {
				extras["components.product_name"] = name
			}
		}
		if len(extras) > 0 {
			result.Extras = extras
		}

		raw, _ := json.Marshal(qr)
		result.Raw = raw
		results <- result
	}

	return quakeResponse
}

func (agent *Agent) queryURL(session *sources.Session, URL string, quakeRequest *Request) (*http.Response, error) {
	body, err := json.Marshal(quakeRequest)
	if err != nil {
		return nil, err
	}

	request, err := sources.NewHTTPRequest(
		http.MethodPost,
		URL,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-QuakeToken", session.Keys.QuakeToken)
	return session.Do(request, agent.Name())
}
