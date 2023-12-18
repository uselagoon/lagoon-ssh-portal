// Package main implements the ssh-portal executable.
package main

import (
	"github.com/alecthomas/kong"
	"github.com/moby/spdystream"
	"go.uber.org/zap"
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
	var log *zap.Logger
	if cli.Debug {
		log = zap.Must(zap.NewDevelopment(zap.AddStacktrace(zap.ErrorLevel)))
	} else {
		log = zap.Must(zap.NewProduction())
	}
	defer log.Sync() //nolint:errcheck
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run(log))
}
