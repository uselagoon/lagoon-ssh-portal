package lagoon

//go:generate enumer -type=UserRole -sql -transform=lower

// UserRole is an enum of valid User roles.
type UserRole int

const (
	// Guest user role.
	Guest UserRole = iota
	// Reporter user role.
	Reporter
	// Developer user role.
	Developer
	// Maintainer user role.
	Maintainer
	// Owner user role.
	Owner
)
