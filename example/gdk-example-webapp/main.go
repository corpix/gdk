package main

import (
	_ "embed"
	"fmt"
	"time"

	"github.com/corpix/gdk/cli"
	"github.com/corpix/gdk/config"
	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/template"
	"github.com/davecgh/go-spew/spew"
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

type TemplateName string

const (
	TemplateNameHello TemplateName = "hello"
)

var (
	//go:embed hello.html
	TemplateHello string

	templates = map[string]string{
		string(TemplateNameHello): TemplateHello,
	}
)

var conf = &Config{}

//

func main() {
	di.MustProvide(di.Default, func() http.RecoverHandler {
		return func(w http.ResponseWriter, r *http.Request, err error) {
			fmt.Println("panic also handled by custom user-defined handler")
		}
	})

	cli.New(
		cli.WithName("gdk-example-webapp"),
		cli.WithUsage("GDK example web application"),
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
				func(h *http.Http, t *template.Template, csrf *http.CsrfTokenService, session *http.SessionService) {
					ts := crypto.NewTokenService(session.Config.TokenConfig.TokenConfig)

					h.Router.
						HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
							w.Header().Add(http.HeaderContentType, http.MimeTextHtml)
							err := t.
								Lookup(string(TemplateNameHello)).
								Execute(w,
									http.NewTemplateContext(r).With(
										http.TemplateContextKeySession,
										http.RequestSessionMustGet(r),
									),
								)
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

					h.Router.
						HandleFunc("/token-service", func(w http.ResponseWriter, r *http.Request) {
							tk := ts.New()
							tk.Header.Meta.Set(crypto.TokenPayloadKeyId, "666")
							tk.Header.Meta.Set(crypto.TokenPayloadKeyAudience, []string{"me", "friends"})
							tk.Set(crypto.TokenPayloadKeyId, "777")
							w.Write(ts.MustEncode(tk))
							w.Write([]byte("\n\n"))
							w.Write([]byte(spew.Sdump(tk)))
						}).
						Methods(http.MethodGet)

					//

					h.Router.
						HandleFunc("/no-csrf", func(w http.ResponseWriter, r *http.Request) {
							t := http.RequestSessionGet(conf.Http.Session, r)
							greet, ok := t.Get("greet")
							if !ok {
								greet = time.Now().String()
								t.Set("greet", greet)
							}
							w.Write([]byte(greet.(string)))
						}).
						Name("no-csrf").
						Methods(http.MethodPost)

					noCsrfPath := http.RoutePathTemplate(h.Router, "no-csrf")
					csrf.SkipPaths(noCsrfPath)
					session.SkipPaths(noCsrfPath)

					//

					h.Router.
						HandleFunc("/panic", func(w http.ResponseWriter, r *http.Request) {
							panic("hello panic")
						})
				},
			),
		),
	).RunAndExitOnError()
}
