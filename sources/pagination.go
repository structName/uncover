package sources

// ClampPageSize returns the per-page size each agent should send upstream.
// engineMax is the API's documented per-page ceiling; limit is query.Limit.
//
// When limit is set and smaller than engineMax, return limit so we don't
// over-fetch a full page just to discard most rows. When limit is unset
// (<= 0, sentinel for "unbounded") or greater than engineMax, return
// engineMax.
//
// Each agent's Query loop should call this once before the pagination
// loop begins, then pass the result into the upstream request struct.
func ClampPageSize(limit, engineMax int) int {
	if limit > 0 && limit < engineMax {
		return limit
	}
	return engineMax
}
