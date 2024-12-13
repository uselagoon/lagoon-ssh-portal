package sshserver

// These variables are exposed for testing only.
var (
	ParseConnectionParams = parseConnectionParams
	ParseLogsArg          = parseLogsArg
	PermissionsMarshal    = permissionsMarshal
	SessionHandler        = sessionHandler
	PubKeyHandler         = pubKeyHandler
)

// Exposes the private ctxKey constants for testing only.
const (
	EnvironmentIDKey   = environmentIDKey
	EnvironmentNameKey = environmentNameKey
	ProjectIDKey       = projectIDKey
	ProjectNameKey     = projectNameKey
)
