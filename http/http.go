package http

import (
	"net/http"

	"path/filepath"

	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/template"
)

type (
	Option         func(*Http)
	Handler        = http.Handler
	HandlerFunc    = http.HandlerFunc
	Middleware     = func(Handler) Handler
	Request        = http.Request
	ResponseWriter = http.ResponseWriter
	Response       = http.Response
	ContextKey     uint8

	Config struct {
		Address          string                  `yaml:"address"`
		Prefix           string                  `yaml:"prefix"`
		BufferedResponse *BufferedResponseConfig `yaml:"buffered-response"`
		Metrics          *MetricsConfig          `yaml:"metrics"`
		Trace            *TraceConfig            `yaml:"trace"`
		Session          *SessionConfig          `yaml:"session"`
		Csrf             *CsrfConfig             `yaml:"csrf"`
		Template         *template.Config        `yaml:"template"`
	}
	Http struct {
		Config  *Config
		Address string
		Router  *Router
	}
)

const (
	MethodGet     = http.MethodGet
	MethodHead    = http.MethodHead
	MethodPost    = http.MethodPost
	MethodPut     = http.MethodPut
	MethodPatch   = http.MethodPatch
	MethodDelete  = http.MethodDelete
	MethodConnect = http.MethodConnect
	MethodOptions = http.MethodOptions
	MethodTrace   = http.MethodTrace

	HeaderRequestId     = "x-request-id"
	HeaderAuthorization = "authorization"
	HeaderContentType   = "content-type"

	AuthTypeBearer = "bearer"
	AuthTypeBasic  = "basic"
)

func (c *Config) Default() {
	if c.BufferedResponse == nil {
		c.BufferedResponse = &BufferedResponseConfig{}
	}
	if c.Metrics == nil {
		c.Metrics = &MetricsConfig{}
	}
	if c.Trace == nil {
		c.Trace = &TraceConfig{}
	}
	if c.Session == nil {
		c.Session = &SessionConfig{TokenConfig: &TokenConfig{}}
	}
	if c.Csrf == nil {
		c.Csrf = &CsrfConfig{TokenConfig: &TokenConfig{}}
	}
	if c.Template == nil {
		c.Template = &template.Config{}
	}

	//

	if c.Metrics.Enable {
		c.Metrics.Default()
		metricsPath := filepath.Join(c.Prefix, c.Metrics.Path)

		c.BufferedResponse.Default()
		c.BufferedResponse.SkipConfig.Default()
		c.BufferedResponse.SkipPaths[metricsPath] = struct{}{}

		c.Trace.Default()
		c.Trace.SkipConfig.Default()
		c.Trace.SkipPaths[metricsPath] = struct{}{}

		c.Session.Default()
		if c.Session.Enable {
			c.Session.SkipConfig.Default()
			c.Session.SkipPaths[metricsPath] = struct{}{}
		}

		c.Csrf.Default()
		if c.Csrf.Enable {
			c.Csrf.SkipConfig.Default()
			c.Csrf.SkipPaths[metricsPath] = struct{}{}
		}
	}
}

func (c *Config) Validate() error {
	if c.Address == "" {
		return errors.New("address should not be empty")
	}
	return nil
}

//

func WithAddress(addr string) Option {
	return func(h *Http) { h.Address = addr }
}

func WithRouter(r *Router) Option {
	return func(h *Http) { h.Router = r }
}

func WithLogAvailableRoutes() Option {
	return func(h *Http) {
		err := h.Router.Walk(func(route *Route, router *Router, ancestors []*Route) error {
			methods, err := route.GetMethods()
			if err != nil {
				return err
			}
			query, err := route.GetQueriesTemplates()
			if err != nil {
				return err
			}
			path, err := route.GetPathTemplate()
			if err != nil {
				return err
			}

			log.Info().
				Str("path", path).
				Strs("query", query).
				Strs("methods", methods).
				Msg("route")

			return nil
		})
		if err != nil {
			panic(err)
		}
	}
}

func WithProvide(cont *di.Container) Option {
	return func(h *Http) {
		di.MustProvide(cont, func() *Http { return h })
	}
}

func WithInvoke(cont *di.Container, f di.Function) Option {
	return func(h *Http) { di.MustInvoke(cont, f) }
}

func WithMiddleware(middlewares ...Middleware) Option {
	return func(h *Http) {
		for _, middleware := range middlewares {
			h.Router.Use(middleware)
		}
	}
}

func (h *Http) ListenAndServe() error {
	if h.Address == "" {
		return errors.New("no address was defined for http server to listen on (use WithAddress Option)")
	}
	if h.Router == nil {
		return errors.New("no router assigned to the server (use WithRouter Option)")
	}
	log.Info().Str("address", h.Address).Msg("starting http server")
	return http.ListenAndServe(h.Address, h.Router)
}

func New(c *Config, options ...Option) *Http {
	h := &Http{
		Config:  c,
		Address: c.Address,
	}
	for _, option := range options {
		option(h)
	}

	return h
}
