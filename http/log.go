package http

import (
	"github.com/felixge/httpsnoop"

	"github.com/corpix/gdk/log"
)

func Log(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		u := *r.URL
		m := httpsnoop.CaptureMetrics(h, w, r)

		log.Info().
			Str("method", r.Method).
			Str("url", u.String()).
			Int("code", m.Code).
			Int64("written", m.Written).
			Dur("duration", m.Duration).
			Msg("request")
	})
}
