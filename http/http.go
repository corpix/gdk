package http

import (
	"net/http"

	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/log"
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
		Address          string                  `yaml:"address,omitempty"`
		BufferedResponse *BufferedResponseConfig `yaml:"buffered-response,omitempty"`
		Metrics          *MetricsConfig          `yaml:"metrics,omitempty"`
		Trace            *TraceConfig            `yaml:"trace,omitempty"`
		Session          *SessionConfig          `yaml:"session,omitempty"`
		Csrf             *CsrfConfig             `yaml:"csrf,omitempty"`
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

	AuthTokenTypeBearer = "bearer"
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

	//

	if c.Metrics.Enable {
		c.Metrics.Default()

		c.BufferedResponse.Default()
		c.BufferedResponse.SkipConfig.Default()
		c.BufferedResponse.SkipPaths[c.Metrics.Path] = struct{}{}

		c.Trace.Default()
		c.Trace.SkipConfig.Default()
		c.Trace.SkipPaths[c.Metrics.Path] = struct{}{}

		c.Session.Default()
		if c.Session.Enable {
			c.Session.SkipConfig.Default()
			c.Session.SkipPaths[c.Metrics.Path] = struct{}{}
		}

		c.Csrf.Default()
		if c.Csrf.Enable {
			c.Csrf.SkipConfig.Default()
			c.Csrf.SkipPaths[c.Metrics.Path] = struct{}{}
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
