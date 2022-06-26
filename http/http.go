package http

import (
	"net/http"

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
	Http           struct {
		Config  *Config
		Address string
		Handler Handler
	}
)

type Config struct {
	Address string         `yaml:"address"`
	Metrics *MetricsConfig `yaml:"metrics"`
	Trace   *TraceConfig   `yaml:"trace"`
}

func (c *Config) Default() {
	if c.Metrics == nil {
		c.Metrics = &MetricsConfig{}
	}
	if c.Trace == nil {
		c.Trace = &TraceConfig{}
	}
}

func (c *Config) Validate() error {
	if c.Address == "" {
		return errors.New("address should not be empty")
	}
	return nil
}

//

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
)

const (
	HeaderRequestId      = "x-request-id"
	HeaderAuthentication = "authentication"
)

const (
	AuthTokenTypeBearer = "bearer"
)

//

func WithAddress(addr string) Option {
	return func(h *Http) { h.Address = addr }
}

func WithHandler(hr Handler) Option {
	return func(h *Http) { h.Handler = hr }
}

func Compose(handler Handler, middlewares ...Middleware) Handler {
	var (
		middlewaresLen = len(middlewares)
		middleware     Middleware
	)
	for n := range middlewares {
		middleware = middlewares[middlewaresLen-1-n]
		handler = middleware(handler)
	}
	return handler
}

func (h *Http) ListenAndServe() error {
	if h.Address == "" {
		return errors.New("no address was defined for http server to listen on (use WithAddress Option)")
	}
	if h.Handler == nil {
		return errors.New("no handler assigned to the server (use WithHandler Option)")
	}
	log.Info().Str("address", h.Address).Msg("starting http server")
	return http.ListenAndServe(h.Address, h.Handler)
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
