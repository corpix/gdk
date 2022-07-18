package main

import (
	"fmt"
	"os"
	"time"

	"github.com/corpix/gdk/cli"
	"github.com/corpix/gdk/config"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/template"
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

	c.Http.Default()
	c.Http.Template.Templates = templates
}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) LogConfig() *log.Config   { return c.Log }
func (c *Config) HttpConfig() *http.Config { return c.Http }

//

var (
	conf      = &Config{}
	templates = map[string]string{
		"hello": `<form method="post"><input type="hidden" name="_csrf" value="{{ csrf .session "/" }}"/><button type="submit"/>send</form>`,
	}
)

//

func main() {
	err := cli.New(
		cli.WithName("gdk-example-app"),
		cli.WithUsage("GDK example application"),
		cli.WithDescription("Example application showing features of GDK"),
		cli.WithConfigTools(
			conf,
			config.YamlUnmarshaler,
			config.YamlMarshaler,
		),
		cli.WithLogTools(conf.LogConfig),
		cli.WithHttpTools(
			conf.HttpConfig,
			http.WithInvoke(
				di.Default,
				func(h *http.Http, g *http.CsrfGenerator, t *template.Template) {
					h.Router.
						HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
							w.Header().Add(http.HeaderContentType, http.MimeTextHtml)
							err := t.
								Lookup("hello").
								Execute(w, map[string]interface{}{
									"session": http.RequestSessionMustGet(r),
								})
							if err != nil {
								panic(err)
							}
						}).
						Methods(http.MethodGet)

					h.Router.
						HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
							t := http.RequestSessionGet(conf.Http.Session, r)
							greet, ok := t.Get("greet")
							if !ok {
								greet = time.Now().String()
								t.Set("greet", greet)
							}
							w.Write([]byte(greet.(string)))
						}).
						Methods(http.MethodPost)
				},
			),
		),
	).Run(os.Args)
	if err != nil {
		// FIXME: wtf, why no log output for error at this stage?
		fmt.Printf("%+v\n", err)
		log.Err(err).Msg("failed to run")
		os.Exit(1)
	}
}
