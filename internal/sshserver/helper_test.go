package sshserver

// ParseConnectionParams exposes the private parseConnectionParams for testing
// only.
var ParseConnectionParams = parseConnectionParams

// ParseLogsArg exposes the private parseLogsArg for testing only.
var ParseLogsArg = parseLogsArg

// SessionHandler exposes the private sessionHandler for testing only.
var SessionHandler = sessionHandler

// PermissionsMarshal exposes the private permissionsMarshal for testing only.
var PermissionsMarshal = permissionsMarshal

// Exposes the private ctxKey constants for testing only.
const (
	EnvironmentIDKey   = environmentIDKey
	EnvironmentNameKey = environmentNameKey
	ProjectIDKey       = projectIDKey
	ProjectNameKey     = projectNameKey
)
