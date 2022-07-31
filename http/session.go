package http

import (
	"context"
	"time"

	"github.com/corpix/gdk/errors"
)

type (
	SessionConfig struct {
		Enable       bool           `yaml:"enable"`
		Refresh      *time.Duration `yaml:"refresh"`
		*TokenConfig `yaml:",inline,omitempty"`
		*SkipConfig  `yaml:",inline,omitempty"`
	}
	Session           = Token
	SessionStore      TokenStore
	SessionValidator  TokenValidator
	SessionPayloadKey string
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

	if c.Validator == nil {
		c.Validator = &TokenValidatorConfig{}
	}
	c.Validator.Default()
	c.Validator.Expire.Default()
	if c.Validator.Expire.MaxAge == nil {
		dur := 24 * time.Hour
		c.Validator.Expire.MaxAge = &dur
	}
	if c.Validator.Expire.TimeDrift == nil {
		dur := 30 * time.Second
		c.Validator.Expire.TimeDrift = &dur
	}
	if c.Refresh == nil {
		dur := *c.Validator.Expire.MaxAge / 2
		c.Refresh = &dur
	}
	if c.SkipConfig == nil {
		c.SkipConfig = &SkipConfig{}
	}
}

func (c *SessionConfig) Validate() error {
	if !c.Enable {
		return nil
	}

	if *c.Refresh <= 0 {
		return errors.New("refresh should be larger than zero")
	}
	return nil
}

var (
	ContextKeySession = new(ContextKey)
)

//

func RequestSessionGet(c *SessionConfig, r *Request) *Session {
	ctxSession := r.Context().Value(ContextKeySession)
	if ctxSession != nil {
		return ctxSession.(*Session)
	}
	return NewToken(c.TokenConfig)
}

func RequestSessionMustGet(r *Request) *Session {
	ctxSession := r.Context().Value(ContextKeySession)
	if ctxSession != nil {
		return ctxSession.(*Session)
	}
	panic("no session in request context")
}

func RequestSessionSet(r *Request, s *Session) *Request {
	return r.WithContext(context.WithValue(r.Context(), ContextKeySession, s))
}

//

func NewSession(c *SessionConfig) *Session {
	return NewToken(c.TokenConfig)
}

func MiddlewareSession(c *SessionConfig, s SessionStore, v SessionValidator) Middleware {
	return func(h Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			if Skip(c.SkipConfig, r) {
				h.ServeHTTP(w, r)
				return
			}

			l := RequestLogGet(r)
			flush := false

			t, err := s.RequestLoad(r)
			if err != nil {
				t = NewSession(c)
				l.Warn().
					Interface("session", t).
					Err(err).
					Msg("failed to load session, created new")
				flush = true
			}

			if *c.Validator.Enable {
				err = v.Validate(t)
				if err != nil {
					l.Warn().
						Interface("session", t).
						Err(err).
						Msg("failed to validate session, creating new")
					t = NewToken(c.TokenConfig)
					flush = true
				}

				if t.Header.ValidAfter.Add(*c.Refresh).Before(time.Now()) {
					tc := NewToken(c.TokenConfig)
					tc.Payload = t.Payload
					l.Trace().
						Interface("expiring-session", t).
						Interface("session", tc).
						Msg("refreshing session")
					t = tc
					flush = true
				}
			}

			//

			r = RequestSessionSet(r, t)

			//

			nonce := t.nonce

			h.ServeHTTP(w, r)

			if flush || t.nonce > nonce {
				_, err = s.RequestSave(w, r, t)
				if err != nil {
					l.Warn().
						Interface("session", t).
						Err(err).
						Msg("failed to save session")
					w.WriteHeader(StatusInternalServerError)
					return
				}
			}
		})
	}
}
