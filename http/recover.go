package http

import (
	"fmt"

	"github.com/corpix/gdk/errors"
)

func Recover(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(StatusInternalServerError)

				l := RequestLog(r)
				var e error
				switch typedErr := err.(type) {
				case error:
					e = typedErr
				default:
					e = errors.New(fmt.Sprint(err))
				}
				l.Error().Stack().Err(e).Msg("panic recover")
			}
		}()
		h.ServeHTTP(w, r)
	})

}
