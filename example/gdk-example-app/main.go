package main

import (
	"github.com/corpix/gdk/cli"
	"github.com/corpix/gdk/config"
	"github.com/corpix/gdk/log"
)

type Config struct {
	Log *log.Config `yaml:"log"`
}

func (c *Config) Default() {
	if c.Log == nil {
		c.Log = &log.Config{}
	}
}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) LogConfig() *log.Config { return c.Log }

var conf = &Config{}

func main() {
	cli.New(
		cli.WithName("gdk-example-app"),
		cli.WithUsage("GDK example application"),
		cli.WithDescription("Example application showing features of GDK"),
		cli.WithConfigTools(
			conf,
			config.YamlUnmarshaler,
			config.YamlMarshaler,
		),
		cli.WithLogTools(conf.LogConfig),
		cli.WithAction(func(ctx *cli.Context) error {
			log.Info().Str("msg", "hello").Msg("greeting")
			return nil
		}),
	).RunAndExitOnError()
}
