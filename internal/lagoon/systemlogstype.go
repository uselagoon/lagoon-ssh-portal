package lagoon

//go:generate go tool enumer -type=SystemLogsType -transform=lower

// SystemLogsType is an enum of valid SystemLogsType types.
type SystemLogsType int

const (
	// InvalidSystemLogsType is an invalid zero value
	InvalidSystemLogsType SystemLogsType = iota
	// Build lagoon system logs type
	Build
	// Task lagoon system logs type
	Task
)
