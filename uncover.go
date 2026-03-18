package uncover

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/sources"
	"github.com/projectdiscovery/uncover/sources/agent/binaryedge"
	"github.com/projectdiscovery/uncover/sources/agent/censys"
	"github.com/projectdiscovery/uncover/sources/agent/criminalip"
	"github.com/projectdiscovery/uncover/sources/agent/driftnet"
	"github.com/projectdiscovery/uncover/sources/agent/fofa"
	"github.com/projectdiscovery/uncover/sources/agent/google"
	"github.com/projectdiscovery/uncover/sources/agent/greynoise"
	"github.com/projectdiscovery/uncover/sources/agent/hunter"
	"github.com/projectdiscovery/uncover/sources/agent/hunterhow"
	"github.com/projectdiscovery/uncover/sources/agent/netlas"
	"github.com/projectdiscovery/uncover/sources/agent/odin"
	"github.com/projectdiscovery/uncover/sources/agent/onyphe"
	"github.com/projectdiscovery/uncover/sources/agent/publicwww"
	"github.com/projectdiscovery/uncover/sources/agent/quake"
	"github.com/projectdiscovery/uncover/sources/agent/shodan"
	"github.com/projectdiscovery/uncover/sources/agent/shodanidb"
	"github.com/projectdiscovery/uncover/sources/agent/zoomeye"

	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var DefaultChannelBuffSize = 32

type Options struct {
	Agents   []string // Uncover Agents to use
	Queries  []string // Queries to pass to Agents
	Limit    int
	MaxRetry int
	Timeout  int
	// Note these ratelimits are used as fallback in case agent
	// ratelimit is not available in DefaultRateLimits
	RateLimit     uint          // default 30 req
	RateLimitUnit time.Duration // default unit
	Proxy         string        // http proxy to use with uncover
}

// Service handler of all uncover Agents
type Service struct {
	Options         *Options
	Agents          []sources.Agent
	Session         *sources.Session
	Provider        *sources.Provider
	Keys            sources.Keys
	UseProviderKeys bool
}

// New creates new uncover service instance
func New(opts *Options) (*Service, error) {
	provider := sources.NewProvider()
	return newService(opts, provider, nil, true)
}

// NewWithProvider creates a new uncover service instance with an injected provider.
func NewWithProvider(opts *Options, provider *sources.Provider) (*Service, error) {
	if provider == nil {
		provider = &sources.Provider{}
	}
	return newService(opts, provider, nil, true)
}

// NewWithKeys creates a new uncover service instance with injected keys.
func NewWithKeys(opts *Options, keys *sources.Keys) (*Service, error) {
	if keys == nil {
		keys = &sources.Keys{}
	}
	return newService(opts, &sources.Provider{}, keys, false)
}

func newService(opts *Options, provider *sources.Provider, keys *sources.Keys, useProviderKeys bool) (*Service, error) {
	s := &Service{
		Agents:          buildAgents(opts.Agents),
		Options:         opts,
		Provider:        provider,
		UseProviderKeys: useProviderKeys,
	}

	if useProviderKeys {
		s.Keys = provider.GetKeys()
	} else {
		s.Keys = *keys
	}

	if opts.RateLimit == 0 {
		opts.RateLimit = 30
	}
	if opts.RateLimitUnit == 0 {
		opts.RateLimitUnit = time.Minute
	}

	var err error
	s.Session, err = sources.NewSession(&s.Keys, opts.MaxRetry, opts.Timeout, 10, opts.Agents, opts.RateLimitUnit, opts.Proxy)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func buildAgents(agentNames []string) []sources.Agent {
	agents := make([]sources.Agent, 0, len(agentNames))
	for _, v := range agentNames {
		switch v {
		case "shodan":
			agents = append(agents, &shodan.Agent{})
		case "censys":
			agents = append(agents, &censys.Agent{})
		case "fofa":
			agents = append(agents, &fofa.Agent{})
		case "shodan-idb":
			agents = append(agents, &shodanidb.Agent{})
		case "quake":
			agents = append(agents, &quake.Agent{})
		case "hunter":
			agents = append(agents, &hunter.Agent{})
		case "zoomeye":
			agents = append(agents, &zoomeye.Agent{})
		case "netlas":
			agents = append(agents, &netlas.Agent{})
		case "criminalip":
			agents = append(agents, &criminalip.Agent{})
		case "publicwww":
			agents = append(agents, &publicwww.Agent{})
		case "hunterhow":
			agents = append(agents, &hunterhow.Agent{})
		case "google":
			agents = append(agents, &google.Agent{})
		case "odin":
			agents = append(agents, &odin.Agent{})
		case "binaryedge":
			agents = append(agents, &binaryedge.Agent{})
		case "onyphe":
			agents = append(agents, &onyphe.Agent{})
		case "driftnet":
			agents = append(agents, &driftnet.Agent{})
		case "greynoise":
			agents = append(agents, &greynoise.Agent{})
		}
	}
	return agents
}

func (s *Service) Execute(ctx context.Context) (<-chan sources.Result, error) {
	// unlikely but as a precaution to handle random panics check all types
	if err := s.nilCheck(); err != nil {
		return nil, err
	}
	switch {
	case len(s.Agents) == 0:
		return nil, errorutil.NewWithTag("uncover", "no agent/source specified")
	case !s.hasAnyAnonymousProvider() && !s.hasKeysAvailable():
		return nil, errorutil.NewWithTag("uncover", "agents %v requires keys but no keys were found", s.Options.Agents)
	}

	megaChan := make(chan sources.Result, DefaultChannelBuffSize)
	// iterate and run all sources
	wg := &sync.WaitGroup{}
	for _, q := range s.Options.Queries {
	agentLabel:
		for _, agent := range s.Agents {
			keys := s.resolveKeysForAgent()
			if keys.Empty() && agent.Name() != "shodan-idb" {
				gologger.Error().Msgf(agent.Name(), "agent given but keys not found")
				continue agentLabel
			}
			session := s.Session.CloneWithKeys(&keys)
			ch, err := agent.Query(session, &sources.Query{
				Query: q,
				Limit: s.Options.Limit,
			})
			if err != nil {
				gologger.Error().Msgf("%s\n", err)
				continue agentLabel
			}
			wg.Add(1)
			go func(source, relay chan sources.Result, ctx context.Context) {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case res, ok := <-source:
						res.Timestamp = time.Now().Unix()
						if !ok {
							return
						}
						relay <- res
					}
				}
			}(ch, megaChan, ctx)
		}
	}

	// close channel when all sources return
	go func(wg *sync.WaitGroup, megaChan chan sources.Result) {
		wg.Wait()
		defer close(megaChan)
	}(wg, megaChan)

	return megaChan, nil
}

func (s *Service) resolveKeysForAgent() sources.Keys {
	if s.UseProviderKeys {
		return s.Provider.GetKeys()
	}
	return s.Keys
}

func (s *Service) hasKeysAvailable() bool {
	if s.UseProviderKeys {
		return s.Provider != nil && s.Provider.HasKeys()
	}
	return !s.Keys.Empty()
}

// ExecuteWithWriters writes output to writer along with stdout
func (s *Service) ExecuteWithCallback(ctx context.Context, callback func(result sources.Result)) error {
	ch, err := s.Execute(ctx)
	if err != nil {
		return err
	}
	if callback == nil {
		return errorutil.NewWithTag("uncover", "result callback cannot be nil")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case result, ok := <-ch:
			if !ok {
				return nil
			}
			callback(result)
		}
	}
}

// AllAgents returns all supported uncover Agents
func (s *Service) AllAgents() []string {
	return []string{
		"shodan", "censys", "fofa", "shodan-idb", "quake", "hunter", "zoomeye", "netlas", "criminalip", "publicwww", "hunterhow", "google", "odin", "binaryedge", "onyphe", "driftnet", "greynoise",
	}
}

func (s *Service) nilCheck() error {
	if s.Provider == nil {
		return errorutil.NewWithTag("uncover", "provider cannot be nil")
	}
	if s.Options == nil {
		return errorutil.NewWithTag("uncover", "options cannot be nil")
	}
	if s.Session == nil {
		return errorutil.NewWithTag("uncover", "session cannot be nil")
	}
	return nil
}

func (s *Service) hasAnyAnonymousProvider() bool {
	return stringsutil.EqualFoldAny("shodan-idb", s.Options.Agents...)
}
