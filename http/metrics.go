package http

import (
	"github.com/prometheus/client_golang/prometheus/promhttp"

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

func WithMetrics(r metrics.RegisterGatherer, rr *Router, options ...MetricsOption) Option {
	return func(h *Http) {
		rr.NewRoute().
			Methods(MethodGet).
			Path("/metrics").
			Handler(MetricsHandler(r, MetricsHandlerFor(r,
				MetricsHandlerConfig{ErrorLog: log.Std(log.Default)},
			)))

		h.Handler = Metrics(h.Handler, options...)
	}
}
