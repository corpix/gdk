package http

import (
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/telemetry"
)

type (
	TelemetryOption        = promhttp.Option
	TelemetryHandlerConfig = promhttp.HandlerOpts
)

var (
	TelemetryHandlerDuration     = promhttp.InstrumentHandlerDuration
	TelemetryHandlerCounter      = promhttp.InstrumentHandlerCounter
	TelemetryHandlerRequestSize  = promhttp.InstrumentHandlerRequestSize
	TelemetryHandlerResponseSize = promhttp.InstrumentHandlerResponseSize
	TelemetryHandlerInFlight     = promhttp.InstrumentHandlerInFlight

	TelemetryHandler    = promhttp.InstrumentMetricHandler
	TelemetryHandlerFor = promhttp.HandlerFor
)

func Telemetry(h Handler, options ...TelemetryOption) Handler {
	labels := []string{
		"code",
		"method",
	}

	duration := telemetry.NewHistogramVec(telemetry.HistogramOpts{
		Name: "request_duration_histogram_seconds",
		Help: "Request time duration.",
	}, labels)
	total := telemetry.NewCounterVec(telemetry.CounterOpts{
		Name: "requests_total",
		Help: "Total number of requests received.",
	}, labels)
	reqSize := telemetry.NewHistogramVec(telemetry.HistogramOpts{
		Name:    "request_size_histogram_bytes",
		Help:    "Request size in bytes.",
		Buckets: []float64{100, 1000, 2000, 5000, 10000},
	}, labels)
	resSize := telemetry.NewHistogramVec(telemetry.HistogramOpts{
		Name:    "response_size_histogram_bytes",
		Help:    "Response size in bytes.",
		Buckets: []float64{100, 1000, 2000, 5000, 10000},
	}, labels)
	inFlight := telemetry.NewGauge(telemetry.GaugeOpts{
		Name: "requests_in_flight",
		Help: "Number of http requests which are currently running.",
	})
	telemetry.MustRegister(
		duration,
		total,
		reqSize,
		resSize,
		inFlight,
	)

	return TelemetryHandlerDuration(duration,
		TelemetryHandlerCounter(total,
			TelemetryHandlerRequestSize(reqSize,
				TelemetryHandlerResponseSize(resSize,
					TelemetryHandlerInFlight(inFlight, h),
					options...,
				),
				options...,
			),
			options...,
		),
		options...,
	)
}

func WithTelemetry(r telemetry.RegisterGatherer, rr *Router, options ...TelemetryOption) Option {
	return func(h *Http) {
		rr.NewRoute().
			Methods(MethodGet).
			Path("/metrics").
			Handler(TelemetryHandler(r, TelemetryHandlerFor(r,
				TelemetryHandlerConfig{ErrorLog: log.Std(log.Default)},
			)))

		h.Handler = Telemetry(h.Handler, options...)
	}
}
