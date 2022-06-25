package main

import (
	"github.com/corpix/gdk/cli"
	"github.com/corpix/gdk/config"
	"github.com/corpix/gdk/log"
)

type Config struct {
	*config.BaseConfig
}

func (c *Config) Default() {
	if c.BaseConfig == nil {
		c.BaseConfig = &config.BaseConfig{}
	}
}

func main() {
	cli.New(
		cli.WithName("gdk-example-app"),
		cli.WithUsage("GDK example application"),
		cli.WithDescription("Example application showing features of GDK"),
		cli.WithConfigTools(
			&Config{},
			config.YamlUnmarshaler,
			config.YamlMarshaler,
		),
		cli.WithLogTools(),
		cli.WithAction(func(ctx *cli.Context) error {
			log.Info().Str("msg", "hello").Msg("greeting")
			return nil
		}),
	).RunAndExitOnError()
}
