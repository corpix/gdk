package http

import (
	"math"
	"math/big"
	"time"

	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/template"
)

type (
	CsrfConfig struct {
		Enable   bool                `yaml:"enable"`
		Granular *bool               `yaml:"granular"`
		Methods  map[string]struct{} `yaml:"methods"`
		Key      string              `yaml:"key"`

		// FIXME: yaml parser insert instance even if this struct does not defined in yaml file
		*TokenConfig `yaml:",inline,omitempty"`
		*SkipConfig  `yaml:",inline,omitempty"`
	}
	Csrf           = Token
	CsrfPayloadKey string
	CsrfGenerator  struct {
		Config        *CsrfConfig
		Container     TokenContainer
		EncodeDecoder TokenEncodeDecoder
	}
)

const (
	CsrfPayloadKeyPath  CsrfPayloadKey = "path"
	CsrfPayloadKeyNonce CsrfPayloadKey = "nonce"

	SessionPayloadKeyCsrfNonce SessionPayloadKey = "csrf-nonce"
)

func (c *CsrfConfig) Default() {
	if !c.Enable {
		return
	}

	if c.Granular == nil {
		v := true
		c.Granular = &v
	}
	if *c.Granular && len(c.Methods) == 0 {
		c.Methods = map[string]struct{}{
			MethodPost:   {},
			MethodPut:    {},
			MethodPatch:  {},
			MethodDelete: {},
		}
	}
	if c.Key == "" {
		c.Key = "_csrf"
	}

	//

	if c.TokenConfig == nil {
		c.TokenConfig = &TokenConfig{}
	}
	c.TokenConfig.Default()

	if c.SkipConfig == nil {
		c.SkipConfig = &SkipConfig{}
	}

	//

	if c.Validator == nil {
		c.Validator = &TokenValidatorConfig{}
	}
	c.Validator.Default()
	c.Validator.Expire.Default()
	if c.Validator.Expire.MaxAge == nil {
		dur := 2 * time.Hour
		c.Validator.Expire.MaxAge = &dur
	}
	if c.Validator.Expire.TimeDrift == nil {
		dur := 30 * time.Second
		c.Validator.Expire.TimeDrift = &dur
	}
}

func (c *CsrfConfig) Validate() error {
	return nil
}

//

func CsrfTokenPathGet(t TokenMap) (string, error) {
	rawPath, ok := t.Get(string(CsrfPayloadKeyPath))
	if !ok {
		return "", errors.Errorf(
			"failed to load %q from csrf token payload",
			CsrfPayloadKeyPath,
		)
	}
	return rawPath.(string), nil
}

func CsrfTokenNonceGet(t TokenMap) (uint, error) {
	rawNonce, ok := t.Get(string(CsrfPayloadKeyNonce))
	if !ok {
		return 0, errors.Errorf(
			"failed to load %q from csrf token payload",
			CsrfPayloadKeyNonce,
		)
	}
	// NOTE: this is because different format parsers use different types
	// when unmarshaling numbers into interface{}
	switch nonce := rawNonce.(type) {
	case float64:
		return uint(nonce), nil
	case uint64:
		return uint(nonce), nil
	case uint:
		return nonce, nil
	case int:
		return uint(nonce), nil
	default:
		panic(errors.Errorf("unknown csrf token nonce type %T for value %+v", rawNonce, rawNonce))
	}
}

func SessionTokenCsrfNonceGet(t TokenMap) (uint, error) {
	rawNonce, ok := t.Get(string(SessionPayloadKeyCsrfNonce))
	if !ok {
		return 0, errors.Errorf(
			"failed to load %q from session token payload",
			SessionPayloadKeyCsrfNonce,
		)
	}
	// NOTE: this is because different format parsers use different types
	// when unmarshaling numbers into interface{}
	switch nonce := rawNonce.(type) {
	case float64:
		return uint(nonce), nil
	case uint64:
		return uint(nonce), nil
	case uint:
		return nonce, nil
	case int:
		return uint(nonce), nil
	default:
		panic(errors.Errorf("unknown session csrf token nonce type %T for value %+v", rawNonce, rawNonce))
	}
}

func SessionTokenCsrfNonceSet(t TokenMap, nonce uint) {
	t.Set(string(SessionPayloadKeyCsrfNonce), nonce)
}

//

func (g *CsrfGenerator) Generate(sess *Session, path string) ([]byte, error) {
	csrf := NewCsrf(g.Config)
	csrf.Payload[string(CsrfPayloadKeyPath)] = path
	nonce, _ := sess.Get(string(SessionPayloadKeyCsrfNonce))
	csrf.Payload[string(CsrfPayloadKeyNonce)] = nonce

	tokenBytes, err := g.Container.Encode(csrf)
	if err != nil {
		return nil, err
	}
	if g.EncodeDecoder != nil {
		return g.EncodeDecoder.Encode(tokenBytes)
	}
	return tokenBytes, nil
}

func (g *CsrfGenerator) GenerateString(sess *Session, path string) (string, error) {
	t, err := g.Generate(sess, path)
	if err != nil {
		return "", err
	}
	return string(t), nil
}

func (g *CsrfGenerator) MustGenerate(sess *Session, path string) []byte {
	t, err := g.Generate(sess, path)
	if err != nil {
		panic(err)
	}
	return t
}

func (g *CsrfGenerator) MustGenerateString(sess *Session, path string) string {
	return string(g.MustGenerate(sess, path))
}

func NewCsrfGenerator(c *CsrfConfig) *CsrfGenerator {
	return &CsrfGenerator{
		Config:        c,
		Container:     NewTokenContainer(c.Container),
		EncodeDecoder: NewTokenEncodeDecoder(c.Encoder),
	}
}

//

func NewCsrf(c *CsrfConfig) *Csrf {
	return NewToken(c.TokenConfig)
}

func MiddlewareCsrf(c *CsrfConfig, g *CsrfGenerator, v TokenValidator) Middleware {
	validationEnable := *c.Validator.Enable
	granular := *c.Granular

	return func(h Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			var (
				err             error
				l               log.Logger
				tokenBytes      []byte
				token           *Csrf
				path            string
				nonce           uint
				session         *Session
				sessionNonceBig *big.Int
				sessionNonce    uint
			)

			if Skip(c.SkipConfig, r) || !validationEnable {
				goto next
			}

			l = RequestLogGet(r)

			session = RequestSessionMustGet(r)
			sessionNonce, err = SessionTokenCsrfNonceGet(session)

			if err != nil {
				l.Warn().Err(err).Msg("failed to get csrf nonce from session payload, generating new")
				sessionNonceBig, err = crypto.RandInt(big.NewInt(math.MaxInt))
				if err != nil {
					l.Error().Err(err).Msg("failed to generate new csrf nonce")
					goto fail
				}
				SessionTokenCsrfNonceSet(session, uint(sessionNonceBig.Uint64()))
			}

			if granular {
				if _, ok := c.Methods[r.Method]; !ok {
					goto next
				}
			}

			//

			tokenBytes = []byte(r.URL.Query().Get(c.Key))
			if len(tokenBytes) == 0 {
				err = r.ParseForm()
				if err != nil {
					l.Warn().Err(err).Msg("failed parse form to get csrf token")
					goto fail
				}
				tokenBytes = []byte(r.Form.Get(c.Key))
			}
			if len(tokenBytes) == 0 {
				l.Warn().Msg("no csrf token in query")
				goto fail
			}

			if g.EncodeDecoder != nil {
				tokenBytes, err = g.EncodeDecoder.Decode(tokenBytes)
				if err != nil {
					l.Warn().
						Bytes("token", tokenBytes).
						Err(err).
						Msg("failed decode csrf token")
					goto fail
				}
			}
			token, err = g.Container.Decode(tokenBytes)
			if err != nil {
				l.Warn().
					Bytes("token", tokenBytes).
					Err(err).
					Msg("failed decode csrf token container")
				goto fail
			}

			err = v.Validate(token)
			if err != nil {
				l.Warn().
					Interface("token", token).
					Err(err).
					Msg("failed to validate csrf")
				goto fail
			}

			//

			path, err = CsrfTokenPathGet(token)
			if err != nil {
				l.Warn().
					Interface("token", token).
					Err(err).
					Msg("failed to get csrf payload key")
				goto fail
			}
			nonce, err = CsrfTokenNonceGet(token)
			if err != nil {
				l.Warn().
					Interface("token", token).
					Err(err).
					Msg("failed to get csrf payload key")
				goto fail
			}

			//

			if nonce != sessionNonce {
				l.Warn().
					Interface("token", token).
					Uint("nonce", nonce).
					Uint("session-nonce", sessionNonce).
					Msg("csrf token nonce does not match csrf nonce stored inside session")
				goto fail
			}
			if path != r.URL.Path {
				l.Warn().
					Interface("token", token).
					Str("path", path).
					Str("url-path", r.URL.Path).
					Msg("csrf token path does not match path from request")
				goto fail
			}

		next:
			h.ServeHTTP(w, r)
			return
		fail:
			w.WriteHeader(StatusBadRequest)
		})
	}
}

func WithCsrfTemplateFuncMap(g *CsrfGenerator) template.Option {
	return func(t *template.Template) {
		t.Funcs(template.FuncMap(map[string]interface{}{
			"csrf": g.MustGenerateString,
		}))
	}
}
