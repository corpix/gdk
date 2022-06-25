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
	ContextKey     uint8
	Response       = http.Response
	Http           struct {
		Address string
		Handler Handler
	}
)

type Config struct {
	Address string `yaml:"address"`
}

func (c *Config) Validate() error {
	if c.Address == "" {
		return errors.New("address should not be empty")
	}
	return nil
}

func WithAddress(addr string) Option {
	return func(h *Http) {
		h.Address = addr
	}
}

func WithHandler(hr Handler) Option {
	return func(h *Http) {
		h.Handler = hr
	}
}

func Compose(handler Handler, middlewares ...Middleware) Handler {
	var (
		middlewaresLen = len(middlewares)
		middleware Middleware
	)
	for n := range middlewares {
		middleware = middlewares[middlewaresLen - 1 - n]
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

func New(options ...Option) *Http {
	h := &Http{}
	for _, option := range options {
		option(h)
	}
	return h
}
