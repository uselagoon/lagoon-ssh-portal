package sshserver

// ParseConnectionParams exposes the private parseConnectionParams for testing
// only.
func ParseConnectionParams(args []string) (string, string, []string) {
	return parseConnectionParams(args)
}
