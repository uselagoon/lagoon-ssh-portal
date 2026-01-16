package lagoon

//go:generate go tool enumer -type=UserRole -transform=lower

// UserRole is an enum of valid User roles.
type UserRole int

const (
	// InvalidUserRole is an invalid zero value
	InvalidUserRole UserRole = iota
	// Guest user role.
	Guest
	// Reporter user role.
	Reporter
	// Developer user role.
	Developer
	// Maintainer user role.
	Maintainer
	// Owner user role.
	Owner
)
