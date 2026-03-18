package sources

import (
	"net/url"
	"strings"
)

func (s *Session) CloneWithKeys(keys *Keys) *Session {
	if s == nil {
		return nil
	}
	clone := *s
	clone.Keys = keys
	return &clone
}

func (s *Session) ResolveBaseURL(engine, defaultBaseURL string) string {
	customBaseURL, ok := normalizeCustomBaseURL(s.lookupBaseURL(engine))
	if ok {
		return customBaseURL
	}
	return defaultBaseURL
}

func (s *Session) ResolveURL(engine, defaultURL string) string {
	customBaseURL, ok := normalizeCustomBaseURL(s.lookupBaseURL(engine))
	if !ok {
		return defaultURL
	}
	return replaceURLBase(defaultURL, customBaseURL)
}

func (s *Session) lookupBaseURL(engine string) string {
	if s == nil || s.Keys == nil {
		return ""
	}
	return s.Keys.BaseURLFor(engine)
}

func normalizeCustomBaseURL(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.User = nil
	return strings.TrimRight(parsed.String(), "/"), true
}

func replaceURLBase(defaultURL, customBaseURL string) string {
	customParsed, err := url.Parse(customBaseURL)
	if err != nil || customParsed.Scheme == "" || customParsed.Host == "" {
		return defaultURL
	}

	remainder := extractURLRemainder(defaultURL)
	schemeHost := customParsed.Scheme + "://" + customParsed.Host
	customPath := strings.TrimRight(customParsed.EscapedPath(), "/")

	switch {
	case customPath == "" && remainder == "":
		return schemeHost
	case customPath == "":
		return schemeHost + ensureLeadingSlash(remainder)
	case remainder == "":
		return schemeHost + customPath
	default:
		return schemeHost + joinURLPath(customPath, remainder)
	}
}

func extractURLRemainder(defaultURL string) string {
	defaultURL = strings.TrimSpace(defaultURL)
	if defaultURL == "" {
		return ""
	}
	if index := strings.Index(defaultURL, "://"); index >= 0 {
		rest := defaultURL[index+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return rest[slash:]
		}
		return ""
	}
	if slash := strings.Index(defaultURL, "/"); slash >= 0 {
		return defaultURL[slash:]
	}
	return ""
}

func ensureLeadingSlash(value string) string {
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "/") {
		return value
	}
	return "/" + value
}

func joinURLPath(basePath, remainder string) string {
	basePath = strings.TrimRight(basePath, "/")
	remainder = ensureLeadingSlash(remainder)
	if remainder == "/" {
		return basePath
	}
	return basePath + remainder
}
