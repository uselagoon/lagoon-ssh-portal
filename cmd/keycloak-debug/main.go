// Package main implements the ssh-portal-api service.
package main

import (
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
)

// CLI represents the command-line interface.
type CLI struct {
	Debug      bool          `kong:"env='DEBUG',help='Enable debug logging'"`
	DumpGroups DumpGroupsCmd `kong:"cmd,default=1,help='(default) Dump top-level Keycloak groups to stdout'"`
}

func main() {
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.UsageOnError(),
	)
	// init logger
	var log *slog.Logger
	if cli.Debug {
		log = slog.New(slog.NewJSONHandler(os.Stderr,
			&slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run(log))
}
