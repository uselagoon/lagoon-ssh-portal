package sshserver

// ParseConnectionParams exposes the private parseConnectionParams for testing
// only.
func ParseConnectionParams(args []string) (string, string, string, []string) {
	return parseConnectionParams(args)
}

// ParseLogsArg exposes the private parseLogsArg for testing only.
func ParseLogsArg(service, logs string, args []string) (bool, int64, error) {
	return parseLogsArg(service, logs, args)
}
