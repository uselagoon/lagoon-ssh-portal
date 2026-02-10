package sshserver

// These variables are exposed for testing only.
var (
	ParseLogsArg                    = parseLogsArg
	ParseExecSessionParams          = parseExecSessionParams
	ParseContainerLogsSessionParams = parseContainerLogsSessionParams
	ParseSystemLogsSessionParams    = parseSystemLogsSessionParams
	ParseSessionType                = parseSessionType
	PermissionsMarshal              = permissionsMarshal
	SessionHandler                  = sessionHandler
	PubKeyHandler                   = pubKeyHandler
)
