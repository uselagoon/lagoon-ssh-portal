package sshserver

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	serviceRegex   = regexp.MustCompile(`^service=(.+)`)
	containerRegex = regexp.MustCompile(`^container=(.+)`)
	logsRegex      = regexp.MustCompile(`^logs=(.+)`)
	tailLinesRegex = regexp.MustCompile(`^tailLines=(\d+)$`)
)

var (
	// ErrCmdArgsAfterLogs is returned when command arguments are found after
	// the logs=... argument.
	ErrCmdArgsAfterLogs = errors.New("command arguments after logs argument")
	// ErrInvalidLogsValue is returned when the value of the logs=...
	// argument is an invalid value.
	ErrInvalidLogsValue = errors.New("invalid logs argument value")
	// ErrNoServiceForLogs is returned when logs=... is specified, but
	// service=... is not.
	ErrNoServiceForLogs = errors.New("missing service argument for logs argument")
)

// parseConnectionParams takes the raw SSH command, and parses out any
// leading service=..., container=..., and logs=... arguments. It returns:
//   - If a service=... argument is given, the value of that argument.
//     If no such argument is given, it falls back to a default of "cli".
//   - If a container=... argument is given, the value of that argument.
//     If no such argument is given, it returns an empty string.
//   - If a logs=... argument is given, the value of that argument.
//     If no such argument is given, it returns an empty string.
//   - The remaining arguments as a slice of strings, with any leading
//     service=, container=, or logs= arguments removed.
//
// Notes about the logic implemented here:
//   - service=... must be given as the first argument to be recognised.
//   - It is an error to specify container=... without service=...
//   - If logs=... is given, it must be the final argument.
//   - If not given in the expected order or with empty values, these
//     parameters may be interpreted as regular command-line arguments.
//
// In manpage syntax:
//
//	[service=... [container=...]] CMD...
//	service=... [container=...] logs=...
func parseConnectionParams(args []string) (string, string, string, []string) {
	// exit early if we have no args
	if len(args) == 0 {
		return "cli", "", "", nil
	}
	// check for service argument
	serviceMatches := serviceRegex.FindStringSubmatch(args[0])
	if len(serviceMatches) == 0 {
		// no service= match, so assume cli and return all args
		return "cli", "", "", args
	}
	service := serviceMatches[1]
	// exit early if we are out of arguments
	if len(args) == 1 {
		return service, "", "", nil
	}
	// check for container and/or logs argument
	containerMatches := containerRegex.FindStringSubmatch(args[1])
	if len(containerMatches) == 0 {
		// no container= match, so check for logs=
		logsMatches := logsRegex.FindStringSubmatch(args[1])
		if len(logsMatches) == 0 {
			// no container= or logs= match, so just return the args
			return service, "", "", args[1:]
		}
		// found logs=, so return it along with the remaining args
		// (which should be empty)
		return service, "", logsMatches[1], args[2:]
	}
	container := containerMatches[1]
	// exit early if we are out of arguments
	if len(args) == 2 {
		return service, container, "", nil
	}
	// container= matched, so check for logs=
	logsMatches := logsRegex.FindStringSubmatch(args[2])
	if len(logsMatches) == 0 {
		// no logs= match, so just return the remaining args
		return service, container, "", args[2:]
	}
	// container= and logs= matched, so return both
	return service, container, logsMatches[1], args[3:]
}

// parseLogsArg checks that:
//   - logs value is one or both of "follow" and "tailLines=n" arguments, comma
//     separated.
//   - n is a positive integer.
//   - if logs is valid, service is not empty.
//   - if logs is valid, cmd is empty.
//
// It returns the follow and tailLines values, and an error if one occurs (or
// nil otherwise).
//
// Note that if multiple tailLines= values are specified, the last one will be
// the value used.
func parseLogsArg(service, logs string, cmd []string) (bool, int64, error) {
	if len(cmd) != 0 {
		return false, 0, ErrCmdArgsAfterLogs
	}
	if service == "" {
		return false, 0, ErrNoServiceForLogs
	}
	var follow bool
	var tailLines int64
	var err error
	for _, arg := range strings.Split(logs, ",") {
		matches := tailLinesRegex.FindStringSubmatch(arg)
		switch {
		case arg == "follow":
			follow = true
		case len(matches) == 2:
			tailLines, err = strconv.ParseInt(matches[1], 10, 64)
			if err != nil {
				return false, 0, ErrInvalidLogsValue
			}
		default:
			return false, 0, ErrInvalidLogsValue
		}
	}
	return follow, tailLines, nil
}
