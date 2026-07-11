package fofa

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
	URL = "https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&fields=%s&page=%d&size=%d&full=%t"
)

var (
	// DefaultPageSize is requested when the caller did not set query.Limit.
	// Picked to balance round-trips against response size; a wide
	// extra_fields list (10+ columns) on a 2000-row page is still ~1MB.
	DefaultPageSize = 2000
	// MaxPageSize is FOFA's documented per-page ceiling; requesting more
	// is silently truncated server-side.
	MaxPageSize = 10000
	// Size kept for backwards compatibility with code that sets it
	// directly. When non-zero, it is used as the floor for the per-page
	// request when query.Limit is unset.
	Size = DefaultPageSize
	// Fields is the fields to return in the results
	Fields = "ip,port,host"

	// if Full is true results from more than one year will be returned
	Full = false
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "fofa"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.FofaKey == "" {
		return nil, errors.New("empty fofa key")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		var numberOfResults int
		page := 1
		pageSize := sources.ClampPageSize(query.Limit, MaxPageSize)
		fields := resolveFields(query.Fields)
		for {
			fofaRequest := &FofaRequest{
				Query:  query.Query,
				Fields: fields,
				Size:   pageSize,
				Page:   page,
				Full:   Full,
			}
			fofaResponse := agent.query(session.ResolveURL(agent.Name(), URL), session, fofaRequest, results)

			if fofaResponse == nil {
				break
			}
			numberOfResults += len(fofaResponse.Results)
			page++
			size := fofaResponse.Size
			if size == 0 || numberOfResults >= query.Limit || len(fofaResponse.Results) == 0 || numberOfResults > size {
				break
			}
		}
	}()

	return results, nil
}

// resolveFields prefers the request-scoped fields parameter; empty falls back
// to the package default so legacy callers keep working.
func resolveFields(requestFields string) string {
	if f := strings.TrimSpace(requestFields); f != "" {
		return f
	}
	return Fields
}

func (agent *Agent) queryURL(session *sources.Session, URL string, fofaRequest *FofaRequest) (*http.Response, error) {
	fields := resolveFields(fofaRequest.Fields)
	base64Query := base64.StdEncoding.EncodeToString([]byte(fofaRequest.Query))
	fofaURL := fmt.Sprintf(
		URL,
		session.Keys.FofaKey,
		base64Query,
		fields,
		fofaRequest.Page,
		fofaRequest.Size,
		fofaRequest.Full,
	)
	request, err := sources.NewHTTPRequest(http.MethodGet, fofaURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, fofaRequest *FofaRequest, results chan sources.Result) *FofaResponse {
	resp, err := agent.queryURL(session, URL, fofaRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	defer func(Body io.ReadCloser) {
		if bodyCloseErr := Body.Close(); bodyCloseErr != nil {
			gologger.Info().Msgf("response body close error : %v", bodyCloseErr)
		}
	}(resp.Body)

	fofaResponse := &FofaResponse{}
	respBodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		results <- sources.Result{Source: agent.Name(), Error: readErr}
		return nil
	}
	if err := json.Unmarshal(respBodyBytes, fofaResponse); err != nil {
		result := sources.Result{
			Source: agent.Name(),
			Raw:    respBodyBytes,
			Error:  fmt.Errorf("failed to decode fofa response: %w", err),
		}
		results <- result
		return nil
	}
	if fofaResponse.Error {
		results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf("%s", fofaResponse.ErrMsg)}
		return nil
	}

	fields := strings.TrimSpace(fofaRequest.Fields)
	if fields == "" {
		fields = Fields
	}
	fieldOrder := parseFieldOrder(fields)
	for _, fofaResult := range fofaResponse.Results {
		result := sources.Result{Source: agent.Name()}
		extras := make(map[string]string, len(fieldOrder))
		for index, field := range fieldOrder {
			if index >= len(fofaResult) {
				continue
			}
			value := strings.TrimSpace(fofaResult[index])
			switch field {
			case "ip":
				result.IP = value
			case "port":
				result.Port, _ = strconv.Atoi(value)
			case "host":
				result.Host = value
			case "link":
				result.Url = value
			}
			if value != "" {
				extras[field] = value
			}
		}
		if len(extras) > 0 {
			result.Extras = extras
		}
		raw, _ := json.Marshal(fofaResult)
		result.Raw = raw
		results <- result
	}
	return fofaResponse
}

func parseFieldOrder(fields string) []string {
	parts := strings.Split(fields, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		field := strings.ToLower(strings.TrimSpace(part))
		if field == "" {
			continue
		}
		result = append(result, field)
	}
	return result
}

type FofaRequest struct {
	Query  string
	Fields string
	Page   int
	Size   int
	Full   bool
}
