package main

import (
	"github.com/alecthomas/kong"
	"go.uber.org/zap"
)

// CLI represents the command-line interface.
type CLI struct {
	Debug   bool       `kong:"env='DEBUG',help='Enable debug logging'"`
	Serve   ServeCmd   `kong:"cmd,default=1,help='(default) Serve ssh-portal-api requests'"`
	Version VersionCmd `kong:"cmd,help='Print version information'"`
}

func main() {
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
