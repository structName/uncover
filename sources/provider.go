package sources

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/projectdiscovery/utils/generic"
)

var (
	UncoverConfigDir = folderutil.AppConfigDirOrDefault(".uncover-config", "uncover")
	// DefaultProviderConfigLocation where keys and config of providers are stored
	DefaultProviderConfigLocation = filepath.Join(UncoverConfigDir, "provider-config.yaml")
)

type Provider struct {
	Shodan            []string `yaml:"shodan"`
	ShodanBaseURL     string   `yaml:"shodan_base_url"`
	ShodanIDBBaseURL  string   `yaml:"shodan_idb_base_url"`
	Censys            []string `yaml:"censys"`
	CensysBaseURL     string   `yaml:"censys_base_url"`
	Fofa              []string `yaml:"fofa"`
	FofaBaseURL       string   `yaml:"fofa_base_url"`
	Quake             []string `yaml:"quake"`
	QuakeBaseURL      string   `yaml:"quake_base_url"`
	Hunter            []string `yaml:"hunter"`
	HunterBaseURL     string   `yaml:"hunter_base_url"`
	ZoomEye           []string `yaml:"zoomeye"`
	ZoomEyeBaseURL    string   `yaml:"zoomeye_base_url"`
	Netlas            []string `yaml:"netlas"`
	NetlasBaseURL     string   `yaml:"netlas_base_url"`
	CriminalIP        []string `yaml:"criminalip"`
	CriminalIPBaseURL string   `yaml:"criminalip_base_url"`
	Publicwww         []string `yaml:"publicwww"`
	PublicwwwBaseURL  string   `yaml:"publicwww_base_url"`
	HunterHow         []string `yaml:"hunterhow"`
	HunterHowBaseURL  string   `yaml:"hunterhow_base_url"`
	Google            []string `yaml:"google"`
	GoogleBaseURL     string   `yaml:"google_base_url"`
	Odin              []string `yaml:"odin"`
	OdinBaseURL       string   `yaml:"odin_base_url"`
	BinaryEdge        []string `yaml:"binaryedge"`
	BinaryEdgeBaseURL string   `yaml:"binaryedge_base_url"`
	Onyphe            []string `yaml:"onyphe"`
	OnypheBaseURL     string   `yaml:"onyphe_base_url"`
	Driftnet          []string `yaml:"driftnet"`
	DriftnetBaseURL   string   `yaml:"driftnet_base_url"`
	GreyNoise         []string `yaml:"greynoise"`
	GreyNoiseBaseURL  string   `yaml:"greynoise_base_url"`
}

// NewProvider loads provider keys from default location and env variables
func NewProvider() *Provider {
	p := &Provider{}
	if err := p.LoadProviderConfig(DefaultProviderConfigLocation); err != nil {
		gologger.Error().Msgf("failed to load provider keys got %v", err)
	}
	p.LoadProviderKeysFromEnv()
	return p
}

func (provider *Provider) GetKeys() Keys {
	keys := Keys{BaseURLs: provider.baseURLMap()}

	if len(provider.Censys) > 0 {
		censysKeys := provider.Censys[rand.Intn(len(provider.Censys))]
		parts := strings.Split(censysKeys, ":")
		if len(parts) == 2 {
			keys.CensysToken = parts[0]
			keys.CensysOrgId = parts[1]
		}
	}

	if len(provider.Shodan) > 0 {
		keys.Shodan = provider.Shodan[rand.Intn(len(provider.Shodan))]
	}

	if len(provider.Fofa) > 0 {
		fofaKeys := provider.Fofa[rand.Intn(len(provider.Fofa))]
		parts := strings.Split(fofaKeys, ":")
		if len(parts) == 2 {
			keys.FofaEmail = parts[0]
			keys.FofaKey = parts[1]
		}
	}

	if len(provider.Quake) > 0 {
		keys.QuakeToken = provider.Quake[rand.Intn(len(provider.Quake))]
	}

	if len(provider.Hunter) > 0 {
		keys.HunterToken = provider.Hunter[rand.Intn(len(provider.Hunter))]
	}

	if len(provider.ZoomEye) > 0 {
		keys.ZoomEyeToken = provider.ZoomEye[rand.Intn(len(provider.ZoomEye))]
	}

	if len(provider.Netlas) > 0 {
		keys.NetlasToken = provider.Netlas[rand.Intn(len(provider.Netlas))]
	}

	if len(provider.CriminalIP) > 0 {
		keys.CriminalIPToken = provider.CriminalIP[rand.Intn(len(provider.CriminalIP))]
	}

	if len(provider.Publicwww) > 0 {
		keys.PublicwwwToken = provider.Publicwww[rand.Intn(len(provider.Publicwww))]
	}
	if len(provider.HunterHow) > 0 {
		keys.HunterHowToken = provider.HunterHow[rand.Intn(len(provider.HunterHow))]
	}
	if len(provider.Google) > 0 {
		googleKeys := provider.Google[rand.Intn(len(provider.Google))]
		parts := strings.Split(googleKeys, ":")
		if len(parts) == 2 {
			keys.GoogleKey = parts[0]
			keys.GoogleCX = parts[1]
		}
	}
	if len(provider.Odin) > 0 {
		keys.OdinToken = provider.Odin[rand.Intn(len(provider.Odin))]
	}
	if len(provider.BinaryEdge) > 0 {
		keys.BinaryEdgeToken = provider.BinaryEdge[rand.Intn(len(provider.BinaryEdge))]
	}
	if len(provider.Onyphe) > 0 {
		keys.OnypheKey = provider.Onyphe[rand.Intn(len(provider.Onyphe))]
	}
	if len(provider.Driftnet) > 0 {
		keys.DriftnetToken = provider.Driftnet[rand.Intn(len(provider.Driftnet))]
	}
	if len(provider.GreyNoise) > 0 {
		keys.GreyNoiseKey = provider.GreyNoise[rand.Intn(len(provider.GreyNoise))]
	}

	return keys
}

func (provider *Provider) baseURLMap() map[string]string {
	baseURLs := make(map[string]string)
	addIfPresent := func(engine, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			baseURLs[engine] = value
		}
	}

	addIfPresent("shodan", provider.ShodanBaseURL)
	addIfPresent("shodan-idb", provider.ShodanIDBBaseURL)
	addIfPresent("censys", provider.CensysBaseURL)
	addIfPresent("fofa", provider.FofaBaseURL)
	addIfPresent("quake", provider.QuakeBaseURL)
	addIfPresent("hunter", provider.HunterBaseURL)
	addIfPresent("zoomeye", provider.ZoomEyeBaseURL)
	addIfPresent("netlas", provider.NetlasBaseURL)
	addIfPresent("criminalip", provider.CriminalIPBaseURL)
	addIfPresent("publicwww", provider.PublicwwwBaseURL)
	addIfPresent("hunterhow", provider.HunterHowBaseURL)
	addIfPresent("google", provider.GoogleBaseURL)
	addIfPresent("odin", provider.OdinBaseURL)
	addIfPresent("binaryedge", provider.BinaryEdgeBaseURL)
	addIfPresent("onyphe", provider.OnypheBaseURL)
	addIfPresent("driftnet", provider.DriftnetBaseURL)
	addIfPresent("greynoise", provider.GreyNoiseBaseURL)

	return baseURLs
}

// LoadProvidersFrom loads provider config from given location
func (provider *Provider) LoadProviderConfig(location string) error {
	if !fileutil.FileExists(location) {
		//create provider config file if it doesn't exist
		if err := fileutil.Marshal(fileutil.YAML, []byte(location), Provider{}); err != nil {
			return errorutil.NewWithTag("uncover", "couldn't write provider config file(%s): %s\n", location, err)
		}
	}
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), provider)
}

// LoadProviderKeysFromEnv loads provider keys from env variables
func (provider *Provider) LoadProviderKeysFromEnv() {
	appendIfExists := func(arr []string, envName string) []string {
		if value, ok := os.LookupEnv(envName); ok {
			return append(arr, value)
		}
		return arr
	}
	provider.Shodan = appendIfExists(provider.Shodan, "SHODAN_API_KEY")
	provider.Hunter = appendIfExists(provider.Hunter, "HUNTER_API_KEY")
	provider.Quake = appendIfExists(provider.Quake, "QUAKE_TOKEN")
	provider.Netlas = appendIfExists(provider.Netlas, "NETLAS_API_KEY")
	provider.CriminalIP = appendIfExists(provider.CriminalIP, "CRIMINALIP_API_KEY")
	provider.Publicwww = appendIfExists(provider.Publicwww, "PUBLICWWW_API_KEY")
	provider.HunterHow = appendIfExists(provider.HunterHow, "HUNTERHOW_API_KEY")
	provider.ZoomEye = appendIfExists(provider.ZoomEye, "ZOOMEYE_API_KEY")
	provider.Driftnet = appendIfExists(provider.Driftnet, "DRIFTNET_API_KEY")

	appendIfAllExists := func(arr []string, env1 string, env2 string) []string {
		if val1, ok := os.LookupEnv(env1); ok {
			if val2, ok2 := os.LookupEnv(env2); ok2 {
				return append(arr, fmt.Sprintf("%s:%s", val1, val2))
			} else {
				gologger.Error().Msgf("%v env variable exists but %v does not", env1, env2)
			}
		}
		return arr
	}
	provider.Fofa = appendIfAllExists(provider.Fofa, "FOFA_EMAIL", "FOFA_KEY")
	provider.Censys = appendIfAllExists(provider.Censys, "CENSYS_API_TOKEN", "CENSYS_ORGANIZATION_ID")
	provider.Google = appendIfAllExists(provider.Google, "GOOGLE_API_KEY", "GOOGLE_API_CX")
	provider.Odin = appendIfExists(provider.Odin, "ODIN_API_KEY")
	provider.BinaryEdge = appendIfExists(provider.BinaryEdge, "BINARYEDGE_API_KEY")
	provider.Onyphe = appendIfExists(provider.Onyphe, "ONYPHE_API_KEY")
	provider.GreyNoise = appendIfExists(provider.GreyNoise, "GREYNOISE_API_KEY")

	assignIfExists := func(target *string, envName string) {
		if value, ok := os.LookupEnv(envName); ok {
			*target = value
		}
	}
	assignIfExists(&provider.ShodanBaseURL, "SHODAN_BASE_URL")
	assignIfExists(&provider.ShodanIDBBaseURL, "SHODAN_IDB_BASE_URL")
	assignIfExists(&provider.CensysBaseURL, "CENSYS_BASE_URL")
	assignIfExists(&provider.FofaBaseURL, "FOFA_BASE_URL")
	assignIfExists(&provider.QuakeBaseURL, "QUAKE_BASE_URL")
	assignIfExists(&provider.HunterBaseURL, "HUNTER_BASE_URL")
	assignIfExists(&provider.ZoomEyeBaseURL, "ZOOMEYE_BASE_URL")
	assignIfExists(&provider.NetlasBaseURL, "NETLAS_BASE_URL")
	assignIfExists(&provider.CriminalIPBaseURL, "CRIMINALIP_BASE_URL")
	assignIfExists(&provider.PublicwwwBaseURL, "PUBLICWWW_BASE_URL")
	assignIfExists(&provider.HunterHowBaseURL, "HUNTERHOW_BASE_URL")
	assignIfExists(&provider.GoogleBaseURL, "GOOGLE_BASE_URL")
	assignIfExists(&provider.OdinBaseURL, "ODIN_BASE_URL")
	assignIfExists(&provider.BinaryEdgeBaseURL, "BINARYEDGE_BASE_URL")
	assignIfExists(&provider.OnypheBaseURL, "ONYPHE_BASE_URL")
	assignIfExists(&provider.DriftnetBaseURL, "DRIFTNET_BASE_URL")
	assignIfExists(&provider.GreyNoiseBaseURL, "GREYNOISE_BASE_URL")
}

// HasKeys returns true if at least one agent/source has keys
func (provider *Provider) HasKeys() bool {
	return generic.EqualsAny(true,
		len(provider.Censys) > 0,
		len(provider.Shodan) > 0,
		len(provider.Fofa) > 0,
		len(provider.Quake) > 0,
		len(provider.Hunter) > 0,
		len(provider.ZoomEye) > 0,
		len(provider.Netlas) > 0,
		len(provider.CriminalIP) > 0,
		len(provider.HunterHow) > 0,
		len(provider.Google) > 0,
		len(provider.Publicwww) > 0,
		len(provider.Odin) > 0,
		len(provider.BinaryEdge) > 0,
		len(provider.Onyphe) > 0,
		len(provider.Driftnet) > 0,
		len(provider.GreyNoise) > 0,
	)
}

func init() {
	// check if config dir exists
	if !fileutil.FolderExists(UncoverConfigDir) {
		if err := fileutil.CreateFolder(UncoverConfigDir); err != nil {
			gologger.Warning().Msgf("couldn't create uncover config dir: %s\n", err)
		}
	}
	// create default provider file if it doesn't exist
	if !fileutil.FileExists(DefaultProviderConfigLocation) {
		if err := fileutil.Marshal(fileutil.YAML, []byte(DefaultProviderConfigLocation), Provider{}); err != nil {
			gologger.Warning().Msgf("couldn't write provider default file: %s\n", err)
		}
	}
}
