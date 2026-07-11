package sources

// Query is a request-scoped search against one agent.
// Fields/Include override package-level defaults when non-empty so concurrent
// callers do not share mutable global agent configuration.
type Query struct {
	Query string
	Limit int
	// Fields is the FOFA fields parameter (comma-separated). Empty → agent default.
	Fields string
	// Include is the Quake include list. Empty → agent default.
	Include []string
}

// Agent is a search provider implementation.
type Agent interface {
	Query(*Session, *Query) (chan Result, error)
	Name() string
}
