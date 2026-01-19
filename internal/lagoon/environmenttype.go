package lagoon

//go:generate go tool enumer -type=EnvironmentType -sql -transform=lower

// EnvironmentType is an enum of valid Environment types.
type EnvironmentType int

const (
	// Development environment type.
	Development EnvironmentType = iota
	// Production environment type.
	Production
)
