package sshserver

import "regexp"

var (
	serviceRegex   = regexp.MustCompile(`service=(.+)`)
	containerRegex = regexp.MustCompile(`container=(.+)`)
)

// parseConnectionParams takes the raw SSH command, and parses out any
// leading service=... and container=... arguments. It returns:
// * If a service=... argument is given, the value of that argument. If no such
//   argument is given, it falls back to a default of "cli".
// * If a container=... argument is given, the value of that argument. If no
//   such argument is given, it returns an empty string.
// * The remaining arguments with any leading service= or container= arguments
//   removed.
//
// Notes about the logic implemented here:
// * container=... may not be specified without service=...
// * service=... must be given as the first argument to be recognised.
// * If not given in the expected order or with empty values, these arguments
//   will be interpreted as regular command-line arguments.
//
// In manpage syntax:
//
//   [service=... [container=...]] CMD...
//
func parseConnectionParams(args []string) (string, string, []string) {
	// exit early if we have no args
	if len(args) == 0 {
		return "cli", "", args
	}
	// check for service argument
	serviceMatches := serviceRegex.FindStringSubmatch(args[0])
	if len(serviceMatches) == 0 {
		return "cli", "", args
	}
	service := serviceMatches[1]
	// exit early if we are out of arguments
	if len(args) < 2 {
		return service, "", args[1:]
	}
	// check for container argument
	containerMatches := containerRegex.FindStringSubmatch(args[1])
	if len(containerMatches) == 0 {
		return service, "", args[1:]
	}
	container := containerMatches[1]
	return service, container, args[2:]
}
