package http

import (
	"context"

	"github.com/felixge/httpsnoop"
	"github.com/google/uuid"

	"github.com/corpix/gdk/log"
)

var (
	ContextKeyRequestId = new(ContextKey)
	ContextKeyLog       = new(ContextKey)
)

func RequestId(r *Request) string {
	ctxRequestId := r.Context().Value(ContextKeyRequestId)
	if ctxRequestId != nil {
		return ctxRequestId.(string)
	}

	return uuid.New().String()
}

func RequestLog(r *Request) log.Logger {
	ctxRequestLog := r.Context().Value(ContextKeyLog)
	if ctxRequestLog != nil {
		return ctxRequestLog.(log.Logger)
	}

	return log.With().
		Str("method", r.Method).
		Str("url", r.URL.String()).
		Logger()
}

func Trace(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		requestId := RequestId(r)
		l := RequestLog(r).
			With().
			Str("request-id", requestId).
			Logger()

		r = r.WithContext(context.WithValue(r.Context(), ContextKeyRequestId, requestId))
		r = r.WithContext(context.WithValue(r.Context(), ContextKeyLog, l))

		m := httpsnoop.CaptureMetrics(h, w, r)

		l.Info().
			Int("code", m.Code).
			Int64("written", m.Written).
			Dur("duration", m.Duration).
			Msg("request")
	})
}
