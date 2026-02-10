package sshserver

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/uselagoon/ssh-portal/internal/k8s"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
)

// SessionType is an enum of valid session types.
type SessionType int

const (
	// InvalidSessionType is an invalid zero value
	InvalidSessionType SessionType = iota
	// Exec session type.
	ExecSession
	// Lagoon container logs session type
	LagoonContainerLogsSession
	// Lagoon system logs session type.
	LagoonSystemLogsSession
)

var (
	serviceRegex      = regexp.MustCompile(`^service=(\S+)`)
	containerRegex    = regexp.MustCompile(`^container=(\S+)`)
	logsRegex         = regexp.MustCompile(`^logs=(\S+)`)
	lagoonSystemRegex = regexp.MustCompile(`^lagoonSystem=(\S+)`)
	nameRegex         = regexp.MustCompile(`^name=(\S+)`)
	tailLinesRegex    = regexp.MustCompile(`^tailLines=(\d+)$`)
)

var (
	// ErrInvalidServiceValue is returned when the value of the service=...
	// argument is invalid.
	ErrInvalidServiceValue = errors.New("invalid service value")
	// ErrInvalidContainerValue is returned when the value of the container=...
	// argument is invalid.
	ErrInvalidContainerValue = errors.New("invalid container value")
	// ErrInvalidNameValue is returned when the value of the name=...
	// argument is invalid.
	ErrInvalidNameValue = errors.New("invalid name value")
	// ErrInvalidLagoonSystemValue is returned when the value of the
	// lagoonSystem=... argument is invalid.
	ErrInvalidLagoonSystemValue = errors.New("invalid lagoonSystem value")
	// ErrInvalidLogsValue is returned when the value of the logs=... argument is
	// invalid.
	ErrInvalidLogsValue = errors.New("invalid logs value")
	// ErrInvalidParserState is returned when the parser enters an invalid state.
	ErrInvalidParserState = errors.New("invalid parser state")
)

// parseSessionType performs a basic inspection of the SSH command to determine
// the session type requested. It returns the determined SessionType.
//
// In manpage syntax, valid commands formats are:
//
//	[service=... [container=...]] CMD...
//	service=... [container=...] logs=...
//	lagoonSystem={build|task} [name=...] logs=...
//
// And the respective session types for each command format are:
//   - ExecSession
//   - LogsSession
//   - LagoonSystemLogsSession
//
// Notes about command parsing:
//   - service=... must be given as the first argument to be recognised.
//   - It is an error to specify container=... without a leading service=...
//   - If logs=... is given, it must be the final argument.
//   - If not given in the expected order or with empty values, these
//     parameters may be interpreted as regular command-line arguments.
func parseSessionType(cmd []string) SessionType {
	switch {
	case len(cmd) == 0:
		return ExecSession
	case serviceRegex.MatchString(cmd[0]):
		switch len(cmd) {
		case 1:
			// valid service=...
			return ExecSession
		case 2:
			if logsRegex.MatchString(cmd[1]) {
				// valid service=... logs=...
				return LagoonContainerLogsSession
			}
			// valid service=... CMD
			return ExecSession
		case 3:
			if containerRegex.MatchString(cmd[1]) && logsRegex.MatchString(cmd[2]) {
				// valid service=... container=... logs=...
				return LagoonContainerLogsSession
			}
			// valid service=... container=... CMD
			return ExecSession
		default:
			// valid service=... CMD...
			return ExecSession
		}
	case lagoonSystemRegex.MatchString(cmd[0]):
		switch len(cmd) {
		case 1:
			// invalid lagoonSystem=...
			return InvalidSessionType
		case 2:
			if logsRegex.MatchString(cmd[1]) {
				// valid lagoonSystem=... logs=...
				return LagoonSystemLogsSession
			}
			// invalid lagoonSystem=... CMD
			return InvalidSessionType
		case 3:
			if nameRegex.MatchString(cmd[1]) && logsRegex.MatchString(cmd[2]) {
				// valid lagoonSystem=... name=... logs=...
				return LagoonSystemLogsSession
			}
			// invalid lagoonSystem=... name=... CMD
			return InvalidSessionType
		default:
			// invalid lagoonSystemLogs=... CMD...
			return InvalidSessionType
		}
	default:
		// valid CMD...
		return ExecSession
	}
}

// parseExecSessionParams takes the split and raw SSH command, and parses any
// leading service=... and container=... arguments. It returns:
//   - If a service=... argument is given, the value of that argument.
//     If no such argument is given, it falls back to a default of "cli".
//   - If a container=... argument is given, the value of that argument.
//     If no such argument is given, it returns an empty string.
//   - The remaining raw SSH command, with any leading service= or container=
//     arguments removed.
//   - An error, if any (nil otherwise).
func parseExecSessionParams(
	cmd []string,
	rawCmd string,
) (string, string, string, error) {
	// exit early if we have no args
	if len(cmd) == 0 {
		return "cli", "", rawCmd, nil
	}
	// check for service argument
	serviceMatches := serviceRegex.FindStringSubmatch(cmd[0])
	if len(serviceMatches) == 0 {
		// no service=... match, so assume service=cli
		return "cli", "", rawCmd, nil
	}
	service := serviceMatches[1]
	if err := k8s.ValidateLabelValue(service); err != nil {
		return "", "", "", ErrInvalidServiceValue
	}
	rawCmd = strings.TrimSpace(serviceRegex.ReplaceAllString(rawCmd, ""))
	// exit early if we are out of arguments
	if len(cmd) == 1 {
		return service, "", rawCmd, nil
	}
	// check for container and/or logs argument
	containerMatches := containerRegex.FindStringSubmatch(cmd[1])
	if len(containerMatches) == 0 {
		// no container=... match, so remaining arguments are CMD
		return service, "", rawCmd, nil
	}
	container := containerMatches[1]
	if err := k8s.ValidateLabelValue(container); err != nil {
		return "", "", "", ErrInvalidContainerValue
	}
	rawCmd = strings.TrimSpace(containerRegex.ReplaceAllString(rawCmd, ""))
	return service, container, rawCmd, nil
}

// parseContainerLogsSessionParams takes the split SSH command, and parses the
// service=..., container=..., and logs=... arguments. It returns:
//   - The value of the service=... argument.
//   - The value of the optional container=... argument. If not given, returns
//     an empty string.
//   - The value of the logs=... argument.
//   - An error, if any (nil otherwise).
func parseContainerLogsSessionParams(
	cmd []string,
) (string, string, string, error) {
	if len(cmd) != 2 && len(cmd) != 3 {
		return "", "", "", ErrInvalidParserState
	}
	serviceMatches := serviceRegex.FindStringSubmatch(cmd[0])
	if len(serviceMatches) == 0 {
		// should be impossible due to previous check in parseSessionType()
		return "", "", "", ErrInvalidParserState
	}
	service := serviceMatches[1]
	var logsArg, container string
	if len(cmd) == 3 {
		// service=... container=... logs=...
		containerMatches := containerRegex.FindStringSubmatch(cmd[1])
		if len(containerMatches) == 0 {
			// should be impossible due to previous check in parseSessionType()
			return "", "", "", ErrInvalidParserState
		}
		container = containerMatches[1]
		logsArg = cmd[2]
	} else {
		logsArg = cmd[1]
	}
	// service=... logs=...
	logsMatches := logsRegex.FindStringSubmatch(logsArg)
	if len(logsMatches) == 0 {
		// should be impossible due to previous check in parseSessionType()
		return "", "", "", ErrInvalidParserState
	}
	if err := k8s.ValidateLabelValue(service); err != nil {
		return "", "", "", ErrInvalidServiceValue
	}
	if err := k8s.ValidateLabelValue(container); err != nil {
		return "", "", "", ErrInvalidContainerValue
	}
	return service, container, logsMatches[1], nil
}

// parseLogsArg checks that:
//   - logs value is one or both of "follow" and "tailLines=n" arguments, comma
//     separated.
//   - n is a non-negative integer.
//
// It returns the follow and tailLines values, and an error if one occurs (or
// nil otherwise).
//
// Note that if multiple tailLines= values are specified, the last one will be
// the value used.
func parseLogsArg(logs string) (bool, int64, error) {
	var follow bool
	var tailLines int64
	var err error
	for arg := range strings.SplitSeq(logs, ",") {
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

// parseSystemLogsSessionParams takes the split SSH command, and parses
// the values of the lagoonSystem=... and logs=... arguments. It returns:
//   - The value of the lagoonSystem=... argument.
//   - The value of the name=... argument. If not given, returns an empty
//     string.
//   - The value of the logs=... argument.
func parseSystemLogsSessionParams(
	cmd []string,
) (lagoon.SystemLogsType, string, string, error) {
	if len(cmd) != 2 && len(cmd) != 3 {
		// should be impossible due to previous check in parseSessionType()
		return lagoon.InvalidSystemLogsType, "", "", ErrInvalidParserState
	}
	lagoonSystemMatches := lagoonSystemRegex.FindStringSubmatch(cmd[0])
	if len(lagoonSystemMatches) == 0 {
		// should be impossible due to previous check in parseSessionType()
		return lagoon.InvalidSystemLogsType, "", "", ErrInvalidParserState
	}
	lagoonSystem, err := lagoon.SystemLogsTypeString(lagoonSystemMatches[1])
	if err != nil {
		return lagoon.InvalidSystemLogsType, "", "", ErrInvalidLagoonSystemValue
	}
	var logsArg, name string
	if len(cmd) == 3 {
		// lagoonSystem=... name=... logs=...
		nameMatches := nameRegex.FindStringSubmatch(cmd[1])
		if len(nameMatches) == 0 {
			// should be impossible due to previous check in parseSessionType()
			return lagoon.InvalidSystemLogsType, "", "", ErrInvalidParserState
		}
		name = nameMatches[1]
		logsArg = cmd[2]
	} else {
		logsArg = cmd[1]
	}
	// lagoonSystem=... logs=...
	logsMatches := logsRegex.FindStringSubmatch(logsArg)
	if len(logsMatches) == 0 {
		// should be impossible due to previous check in parseSessionType()
		return lagoon.InvalidSystemLogsType, "", "", ErrInvalidParserState
	}
	if err := k8s.ValidateLabelValue(name); err != nil {
		return lagoon.InvalidSystemLogsType, "", "", ErrInvalidNameValue
	}
	return lagoonSystem, name, logsMatches[1], nil
}
