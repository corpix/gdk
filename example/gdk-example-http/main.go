package main

import (
	"time"

	"github.com/corpix/gdk/cli"
	"github.com/corpix/gdk/config"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/log"
)

type Config struct {
	Log  *log.Config  `yaml:"log"`
	Http *http.Config `yaml:"http"`
}

func (c *Config) Default() {
	if c.Log == nil {
		c.Log = &log.Config{}
	}
	if c.Http == nil {
		c.Http = &http.Config{}
	}
}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) LogConfig() *log.Config   { return c.Log }
func (c *Config) HttpConfig() *http.Config { return c.Http }

var conf = &Config{}

//

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
		cli.WithHttpTools(conf.HttpConfig,
			http.WithInvoke(
				di.Default,
				func(h *http.Http) {
					h.Router.
						HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
							t := http.RequestSessionGet(conf.Http.Session, r)
							greet, ok := t.Get("greet")
							if !ok {
								greet = time.Now().String()
								t.Set("greet", greet)
							}
							w.Write([]byte(greet.(string)))
						})
					h.Router.
						HandleFunc("/panic", func(w http.ResponseWriter, r *http.Request) {
							panic("hello panic")
						})
				},
			),
		),
		cli.WithAction(func(ctx *cli.Context) error {
			log.Info().Str("msg", "hello").Msg("greeting")
			return nil
		}),
	).RunAndExitOnError()
}
