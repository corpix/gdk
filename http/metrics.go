package http

import (
	"crypto/subtle"
	"io/ioutil"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/metrics"
)

type (
	MetricsOption        = promhttp.Option
	MetricsHandlerConfig = promhttp.HandlerOpts
)

var (
	MetricsHandlerDuration     = promhttp.InstrumentHandlerDuration
	MetricsHandlerCounter      = promhttp.InstrumentHandlerCounter
	MetricsHandlerRequestSize  = promhttp.InstrumentHandlerRequestSize
	MetricsHandlerResponseSize = promhttp.InstrumentHandlerResponseSize
	MetricsHandlerInFlight     = promhttp.InstrumentHandlerInFlight

	MetricsHandler    = promhttp.InstrumentMetricHandler
	MetricsHandlerFor = promhttp.HandlerFor
)

//

type MetricsConfig struct {
	Enable    bool   `yaml:"enable"`
	Log       *bool  `yaml:"log"`
	Path      string `yaml:"path"`
	TokenType string `yaml:"token-type"`
	Token     string `yaml:"token"`
	TokenFile string `yaml:"token-file"`
}

func (c *MetricsConfig) Default() {
	if c.Log == nil {
		v := false
		c.Log = &v
	}
	if c.Path == "" {
		c.Path = "/metrics"
	}
	if c.TokenType == "" {
		c.TokenType = AuthTokenTypeBearer
	}
}

func (c *MetricsConfig) Validate() error {
	if c.Token != "" && c.TokenFile != "" {
		return errors.New("either define token or token-file, not both of them")
	}

	if strings.ToLower(c.TokenType) != AuthTokenTypeBearer {
		// TODO: more token types + token encoding? not sure we need it now, but in future... maybe
		return errors.New("at this moment only bearer token type is supported")
	}
	return nil
}

func (c *MetricsConfig) Expand() error {
	c.TokenType = strings.ToLower(c.TokenType)

	// println("foo")
	// FIXME: expansion called multiple times? why?
	if c.TokenFile != "" {
		tokenBytes, err := ioutil.ReadFile(c.TokenFile)
		if err != nil {
			return errors.Wrapf(err, "failed to read token file at %q", c.TokenFile)
		}
		c.Token = string(tokenBytes)
	}
	return nil
}

//

func Metrics(h Handler, options ...MetricsOption) Handler {
	labels := []string{
		"code",
		"method",
	}

	duration := metrics.NewHistogramVec(metrics.HistogramOpts{
		Name: "request_duration_histogram_seconds",
		Help: "Request time duration.",
	}, labels)
	total := metrics.NewCounterVec(metrics.CounterOpts{
		Name: "requests_total",
		Help: "Total number of requests received.",
	}, labels)
	reqSize := metrics.NewHistogramVec(metrics.HistogramOpts{
		Name:    "request_size_histogram_bytes",
		Help:    "Request size in bytes.",
		Buckets: []float64{100, 1000, 2000, 5000, 10000},
	}, labels)
	resSize := metrics.NewHistogramVec(metrics.HistogramOpts{
		Name:    "response_size_histogram_bytes",
		Help:    "Response size in bytes.",
		Buckets: []float64{100, 1000, 2000, 5000, 10000},
	}, labels)
	inFlight := metrics.NewGauge(metrics.GaugeOpts{
		Name: "requests_in_flight",
		Help: "Number of http requests which are currently running.",
	})
	metrics.MustRegister(
		duration,
		total,
		reqSize,
		resSize,
		inFlight,
	)

	return MetricsHandlerDuration(duration,
		MetricsHandlerCounter(total,
			MetricsHandlerRequestSize(reqSize,
				MetricsHandlerResponseSize(resSize,
					MetricsHandlerInFlight(inFlight, h),
					options...,
				),
				options...,
			),
			options...,
		),
		options...,
	)
}

func WithMetricsHandler(r metrics.RegisterGatherer, rr *Router, options ...MetricsOption) Option {
	return func(h *Http) {
		if !h.Config.Metrics.Enable {
			return
		}

		subr := rr.NewRoute().Subrouter()

		if h.Config.Metrics.Token == "" {
			// NOTE: TokenFile contents will be loaded into Token field
			log.Warn().
				Msg("metrics token is not defined, likely this is not what you want, please define metrics.token or metrics.token-file")
		} else {
			subr.Use(func(next Handler) Handler {
				subjectAuthentication := h.Config.Metrics.TokenType + " " + h.Config.Metrics.Token
				return HandlerFunc(func(w ResponseWriter, r *Request) {
					clientAuthentication := r.Header.Get(HeaderAuthentication)
					if subtle.ConstantTimeCompare(
						[]byte(subjectAuthentication),
						[]byte(clientAuthentication),
					) == 1 {
						next.ServeHTTP(w, r)
						return
					}

					l := RequestLogGet(r)
					l.Warn().Msg("authentication failed, token does not match")

					w.WriteHeader(StatusNotFound)
				})
			})
		}

		subr.
			Methods(MethodGet).
			Path(h.Config.Metrics.Path).
			Handler(MetricsHandler(r, MetricsHandlerFor(r,
				MetricsHandlerConfig{ErrorLog: log.Std(log.Default)},
			)))

		h.Handler = Metrics(h.Handler, options...)
	}
}
