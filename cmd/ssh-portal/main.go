// Package main implements the ssh-portal service.
package main

import (
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/moby/spdystream"
)

// CLI represents the command-line interface.
type CLI struct {
	Debug   bool       `kong:"env='DEBUG',help='Enable debug logging'"`
	Serve   ServeCmd   `kong:"cmd,default=1,help='(default) Serve ssh-portal requests'"`
	Version VersionCmd `kong:"cmd,help='Print version information'"`
}

func main() {
	// work around https://github.com/moby/spdystream/issues/87
	spdystream.DEBUG = ""
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
