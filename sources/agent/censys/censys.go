package censys

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	censyssdkgo "github.com/censys/censys-sdk-go"
	"github.com/censys/censys-sdk-go/models/components"
	"github.com/censys/censys-sdk-go/models/operations"
	"github.com/projectdiscovery/uncover/sources"
)

const (
	MaxPerPage = 100
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "censys"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.CensysToken == "" || session.Keys.CensysOrgId == "" {
		return nil, errors.New("empty censys keys")
	}

	// Create the Censys SDK client once
	s := censyssdkgo.New(
		censyssdkgo.WithOrganizationID(session.Keys.CensysOrgId),
		censyssdkgo.WithSecurity(session.Keys.CensysToken),
		censyssdkgo.WithClient(
			session.Client.HTTPClient,
		),
	)

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		var numberOfResults int
		nextCursor := ""
		for {
			censysRequest := &CensysRequest{
				Query:   query.Query,
				PerPage: MaxPerPage,
				Cursor:  nextCursor,
			}
			censysResponse := agent.query(session, s, censysRequest, results)
			if censysResponse == nil {
				break
			}
			hasNextCursor := false
			if censysResponse.ResponseEnvelopeSearchQueryResponse.Result != nil && censysResponse.ResponseEnvelopeSearchQueryResponse.Result.NextPageToken != "" {
				hasNextCursor = true
			}

			if !hasNextCursor || numberOfResults > query.Limit || len(censysResponse.ResponseEnvelopeSearchQueryResponse.Result.Hits) == 0 {
				break
			}
			nextCursor = censysResponse.ResponseEnvelopeSearchQueryResponse.Result.NextPageToken
			numberOfResults += len(censysResponse.ResponseEnvelopeSearchQueryResponse.Result.Hits)
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(s *censyssdkgo.SDK, censysRequest *CensysRequest) (*operations.V3GlobaldataSearchQueryResponse, error) {
	ctx := context.Background()

	return s.GlobalData.Search(ctx, operations.V3GlobaldataSearchQueryRequest{
		SearchQueryInputBody: components.SearchQueryInputBody{
			PageSize:  censyssdkgo.Int64(int64(censysRequest.PerPage)),
			Query:     censysRequest.Query,
			PageToken: &censysRequest.Cursor,
		},
	})
}

func (agent *Agent) query(session *sources.Session, s *censyssdkgo.SDK, censysRequest *CensysRequest, results chan sources.Result) *operations.V3GlobaldataSearchQueryResponse {
	// query certificates
	resp, err := agent.queryURL(s, censysRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		// httputil.DrainResponseBody(resp)
		return nil
	}

	if result := resp.ResponseEnvelopeSearchQueryResponse.Result; result != nil {
		for _, censysResult := range result.Hits {

			for _, host := range censysResult.WebpropertyV1.Resource.Endpoints {
				r := sources.Result{Source: agent.Name()}
				if host.IP != nil {
					r.IP = *host.IP
				}
				if host.Hostname != nil {
					r.Host = *host.Hostname
				}
				if host.Port != nil {
					r.Port = *host.Port
				}
				if host.HTTP != nil && host.HTTP.URI != nil {
					r.Url = *host.HTTP.URI
				}

				extras := map[string]string{}
				if host.HTTP != nil {
					if host.HTTP.HTMLTitle != nil && *host.HTTP.HTMLTitle != "" {
						extras["http.title"] = *host.HTTP.HTMLTitle
					}
					if host.HTTP.StatusCode != nil && *host.HTTP.StatusCode > 0 {
						extras["http.status_code"] = strconv.Itoa(*host.HTTP.StatusCode)
					}
				}
				if host.Banner != nil && *host.Banner != "" {
					extras["banner"] = *host.Banner
				}
				if len(extras) > 0 {
					r.Extras = extras
				}

				raw, _ := json.Marshal(host)
				r.Raw = raw
				results <- r
			}

		}
	}

	return resp
}

type CensysRequest struct {
	Query   string
	PerPage int
	Cursor  string
}
