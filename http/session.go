package http

import (
	"context"
	"time"
)

type (
	SessionConfig struct {
		Enable       bool `yaml:"enable"`
		*TokenConfig `yaml:",inline"`
	}
)

func (c *SessionConfig) Default() {
	if !c.Enable {
		return
	}

	if c.TokenConfig == nil {
		c.TokenConfig = &TokenConfig{}
	}
	c.TokenConfig.Default()

	if c.Store == nil {
		c.Store = &TokenStoreConfig{}
	}
	if c.Store.Type == "" {
		c.Store.Type = string(TokenStoreTypeCookie)
	}
}

var (
	ContextKeySession = new(ContextKey)
)

//

func RequestSessionGet(c *SessionConfig, r *Request) *Token {
	ctxSession := r.Context().Value(ContextKeySession)
	if ctxSession != nil {
		return ctxSession.(*Token)
	}
	return NewToken(c.TokenConfig)
}

func RequestSessionSet(r *Request, s *Token) *Request {
	return r.WithContext(context.WithValue(r.Context(), ContextKeySession, s))
}

//

func Session(c *SessionConfig, s TokenStore, v *TokenValidator) Middleware {
	return func(h Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			l := RequestLogGet(r)
			flush := false

			t, err := s.Load(r)
			if err != nil {
				l.Warn().Err(err).Msg("failed to load session, creating new")
				t = NewToken(c.TokenConfig)
				flush = true
			}

			if *c.Validator.Enable {
				err = v.Validate(t)
				if err != nil {
					l.Warn().Err(err).Msg("failed to validate session, creating new")
					t = NewToken(c.TokenConfig)
					flush = true
				}

				if t.Header.ValidAfter.Add(*c.Validator.Refresh).Before(time.Now()) {
					tc := NewToken(c.TokenConfig)
					tc.Payload = t.Payload
					t = tc
					flush = true
				}
			}

			//

			r = RequestSessionSet(r, t)
			bw := NewBufferedResponseWriter(w)
			defer bw.Flush()

			//

			nonce := t.nonce

			h.ServeHTTP(bw, r)

			if flush || t.nonce > nonce {
				err = s.Save(bw, t)
				if err != nil {
					l.Warn().Err(err).Msg("failed to save session")
					w.WriteHeader(StatusInternalServerError)
					return
				}
			}
		})
	}
}
