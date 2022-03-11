package main

import "fmt"

var (
	date        string
	goVersion   string
	shortCommit string
	version     string
)

// VersionCmd represents the version command.
type VersionCmd struct{}

// Run the version command to print version information.
func (cmd *VersionCmd) Run() error {
	fmt.Printf("Lagoon ssh-portal-api %v (%v) compiled with %v on %v\n", version,
		shortCommit, goVersion, date)
	return nil
}
