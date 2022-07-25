package http

import (
	"fmt"

	"github.com/corpix/gdk/errors"
)

func MiddlewareRecover(handler func(error)) Middleware {
	return func(h Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			defer func() {
				if err := recover(); err != nil {
					w.WriteHeader(StatusInternalServerError)

					l := RequestLogGet(r)
					var e error
					switch typedErr := err.(type) {
					case error:
						e = typedErr
					default:
						e = errors.New(fmt.Sprint(err))
					}
					e = errors.WithStack(e)
					l.Error().Stack().Err(e).Msg("panic recover")
					if handler != nil {
						handler(e)
					}
				}
			}()
			h.ServeHTTP(w, r)
		})
	}
}
