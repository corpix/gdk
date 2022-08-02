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
	Session              = Token
	SessionStore         TokenStore
	SessionValidator     TokenValidator
	SessionEncodeDecoder TokenEncodeDecoder
	SessionContainer     TokenContainer
	SessionPayloadKey    string
	SessionService       struct {
		Config        *SessionConfig
		Container     SessionContainer
		EncodeDecoder SessionEncodeDecoder
		Validator     SessionValidator
		Store         SessionStore
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

func NewSessionService(c *SessionConfig) *SessionService {
	srv := &SessionService{
		Config:        c,
		Container:     NewTokenContainer(c.Container),
		EncodeDecoder: NewTokenEncodeDecoder(c.Encoder),
		Validator:     NewTokenValidator(c.Validator),
	}

	store, err := NewTokenStore(c.Store, srv.Container, srv.EncodeDecoder)
	if err != nil {
		panic(err)
	}

	srv.Store = store
	return srv
}

func MiddlewareSession(srv *SessionService) Middleware {
	return func(h Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			if Skip(srv.Config.SkipConfig, r) {
				h.ServeHTTP(w, r)
				return
			}

			l := RequestLogGet(r)
			flush := false

			t, err := srv.Store.RequestLoad(r)
			if err != nil {
				t = NewSession(srv.Config)
				l.Warn().
					Interface("session", t).
					Err(err).
					Msg("failed to load session, created new")
				flush = true
			}

			if *srv.Config.Validator.Enable {
				err = srv.Validator.Validate(t)
				if err != nil {
					l.Warn().
						Interface("session", t).
						Err(err).
						Msg("failed to validate session, creating new")
					t = NewSession(srv.Config)
					flush = true
				}

				if t.Header.ValidAfter.Add(*srv.Config.Refresh).Before(time.Now()) {
					tc := NewSession(srv.Config)
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
				_, err = srv.Store.RequestSave(w, r, t)
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
