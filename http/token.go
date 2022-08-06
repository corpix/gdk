package http

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"time"

	jwt "github.com/cristalhq/jwt/v4"
	"github.com/google/uuid"
	"github.com/philippgille/gokv/redis"
	msgpack "github.com/vmihailenco/msgpack/v5"

	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/encoding"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/kv"
)

type (
	TokenConfig struct {
		Store     *TokenStoreConfig     `yaml:"store,omitempty"`
		Container *TokenContainerConfig `yaml:"container"`
		Encoder   string                `yaml:"encoder"`
		Validator *TokenValidatorConfig `yaml:"validator"`
	}
	Token struct {
		seqno   uint
		Header  TokenHeader  `json:"header"`
		Payload TokenPayload `json:"payload"`
	}
	TokenHeader struct {
		ValidAfter  time.Time `json:"valid-after"`
		ValidBefore time.Time `json:"valid-before"`
	}
	TokenPayload    map[string]interface{}
	TokenPayloadKey string
	TokenMap        interface {
		Get(key string) (interface{}, bool)
		Set(key string, value interface{})
		Del(key string)
	}

	TokenJwt struct {
		jwt.RegisteredClaims
		Payload TokenPayload `json:"payload"`
	}
	TokenJwtAlgorithm = jwt.Algorithm
	TokenJwtHeader    = jwt.Header

	//

	TokenStoreConfig struct {
		Type   string                  `yaml:"type"`
		Cookie *TokenStoreCookieConfig `yaml:"cookie"`
		Redis  *TokenStoreRedisConfig  `yamnl:"redis"`
	}
	TokenStoreType string
	TokenStore     interface {
		Id(*Request) ([]byte, error)
		Save(*Token) ([]byte, error)
		RequestSave(ResponseWriter, *Request, *Token) ([]byte, error)
		Load([]byte) (*Token, error)
		RequestLoad(*Request) (*Token, error)
		Drop([]byte) error
		RequestDrop(ResponseWriter, *Request) error
	}

	TokenStoreCookieConfig struct {
		Name     string         `yaml:"name"`
		Path     string         `yaml:"path"`
		Domain   string         `yaml:"domain"`
		MaxAge   *time.Duration `yaml:"max-age,omitempty"`
		Secure   *bool          `yaml:"secure,omitempty"`
		HttpOnly *bool          `yaml:"httponly,omitempty"`
		SameSite string         `yaml:"same-site"`
	}
	TokenStoreCookie struct {
		Config        *TokenStoreCookieConfig
		Container     TokenContainer
		EncodeDecoder TokenEncodeDecoder
	}

	TokenStoreRedisConfig struct {
		Address      string                  `yaml:"address"`
		Password     string                  `yaml:"password"`
		PasswordFile string                  `yaml:"password-file"`
		Db           int                     `yaml:"db"`
		Cookie       *TokenStoreCookieConfig `yaml:"cookie"` // NOTE: we store id in cookie

		password string
	}
	TokenStoreRedis struct {
		Config        *TokenStoreRedisConfig
		Container     TokenContainer
		EncodeDecoder TokenEncodeDecoder
		Store         kv.Store
	}

	//

	TokenContainerConfig struct {
		Type      string                         `yaml:"type"`
		Json      *TokenContainerJsonConfig      `yaml:"json,omitempty"`
		Jwt       *TokenContainerJwtConfig       `yaml:"jwt,omitempty"`
		Msgpack   *TokenContainerMsgpackConfig   `yaml:"msgpack,omitempty"`
		SecretBox *TokenContainerSecretBoxConfig `yaml:"secretbox,omitempty"`
	}
	TokenContainerType       string
	TokenContainerJsonConfig struct{}
	TokenContainerJwtConfig  struct {
		Algorithm string `yaml:"algorithm"`

		Key     string `yaml:"key,omitempty"`
		KeyFile string `yaml:"key-file,omitempty"`
		key     []byte
	}
	TokenContainerMsgpackConfig   struct{}
	TokenContainerSecretBoxConfig struct {
		Key       string `yaml:"key,omitempty"`
		KeyFile   string `yaml:"key-file,omitempty"`
		key       crypto.SecretBoxKey
		Container *TokenContainerConfig `yaml:"container"`
	}

	TokenContainer interface {
		Encode(*Token) ([]byte, error)
		Decode([]byte) (*Token, error)
	}
	TokenContainerJson struct {
		Config *TokenContainerJsonConfig
	}
	TokenContainerJwt struct {
		Config   *TokenContainerJwtConfig
		Builder  *jwt.Builder
		Verifier jwt.Verifier
	}
	TokenContainerMsgpack struct {
		Config *TokenContainerMsgpackConfig
	}
	TokenContainerSecretBox struct {
		Config    *TokenContainerSecretBoxConfig
		Container TokenContainer
		SecretBox *crypto.SecretBox
	}

	TokenEncodeDecoderType string
	TokenEncodeDecoder     encoding.EncodeDecoder

	TokenValidatorConfig struct {
		Enable *bool                       `yaml:"enable"`
		Type   string                      `yaml:"type"`
		Expire *TokenValidatorExpireConfig `yaml:"expire"`
	}
	TokenValidatorExpireConfig struct {
		MaxAge    *time.Duration `yaml:"max-age"`
		TimeDrift *time.Duration `yaml:"time-drift"`
	}
	TokenValidatorType string
	TokenValidator     interface {
		Validate(*Token) error
	}
	TokenValidatorExpire struct {
		Config *TokenValidatorExpireConfig
	}
)

const (
	TokenPayloadKeyId TokenPayloadKey = "id"

	TokenStoreTypeCookie TokenStoreType = "cookie"
	TokenStoreTypeRedis  TokenStoreType = "redis"

	TokenEncodeDecoderTypeRaw    TokenEncodeDecoderType = "raw"
	TokenEncodeDecoderTypeBase64 TokenEncodeDecoderType = "base64"

	TokenContainerTypeJson      TokenContainerType = "json"
	TokenContainerTypeJwt       TokenContainerType = "jwt"
	TokenContainerTypeMsgpack   TokenContainerType = "msgpack"
	TokenContainerTypeSecretBox TokenContainerType = "secretbox"

	TokenJwtAlgorithmEdDSA TokenJwtAlgorithm = jwt.EdDSA
	TokenJwtAlgorithmHS256 TokenJwtAlgorithm = jwt.HS256
	TokenJwtAlgorithmHS384 TokenJwtAlgorithm = jwt.HS384
	TokenJwtAlgorithmHS512 TokenJwtAlgorithm = jwt.HS512
	TokenJwtAlgorithmRS256 TokenJwtAlgorithm = jwt.RS256
	TokenJwtAlgorithmRS384 TokenJwtAlgorithm = jwt.RS384
	TokenJwtAlgorithmRS512 TokenJwtAlgorithm = jwt.RS512
	TokenJwtAlgorithmES256 TokenJwtAlgorithm = jwt.ES256
	TokenJwtAlgorithmES384 TokenJwtAlgorithm = jwt.ES384
	TokenJwtAlgorithmES512 TokenJwtAlgorithm = jwt.ES512
	TokenJwtAlgorithmPS256 TokenJwtAlgorithm = jwt.PS256
	TokenJwtAlgorithmPS384 TokenJwtAlgorithm = jwt.PS384
	TokenJwtAlgorithmPS512 TokenJwtAlgorithm = jwt.PS512

	TokenValidatorTypeExpire TokenValidatorType = "expire"
)

var (
	ContextKeyToken = new(ContextKey)

	TokenJwtAlgorithms = map[string]TokenJwtAlgorithm{
		strings.ToLower(string(TokenJwtAlgorithmEdDSA)): TokenJwtAlgorithmEdDSA,
		strings.ToLower(string(TokenJwtAlgorithmHS256)): TokenJwtAlgorithmHS256,
		strings.ToLower(string(TokenJwtAlgorithmHS384)): TokenJwtAlgorithmHS384,
		strings.ToLower(string(TokenJwtAlgorithmHS512)): TokenJwtAlgorithmHS512,
		strings.ToLower(string(TokenJwtAlgorithmRS256)): TokenJwtAlgorithmRS256,
		strings.ToLower(string(TokenJwtAlgorithmRS384)): TokenJwtAlgorithmRS384,
		strings.ToLower(string(TokenJwtAlgorithmRS512)): TokenJwtAlgorithmRS512,
		strings.ToLower(string(TokenJwtAlgorithmES256)): TokenJwtAlgorithmES256,
		strings.ToLower(string(TokenJwtAlgorithmES384)): TokenJwtAlgorithmES384,
		strings.ToLower(string(TokenJwtAlgorithmES512)): TokenJwtAlgorithmES512,
		strings.ToLower(string(TokenJwtAlgorithmPS256)): TokenJwtAlgorithmPS256,
		strings.ToLower(string(TokenJwtAlgorithmPS384)): TokenJwtAlgorithmPS384,
		strings.ToLower(string(TokenJwtAlgorithmPS512)): TokenJwtAlgorithmPS512,
	}

	TokenJwtErrInvalidFormat     = jwt.ErrInvalidFormat
	TokenJwtErrAlgorithmMismatch = jwt.ErrAlgorithmMismatch
	TokenJwtErrInvalidSignature  = jwt.ErrInvalidSignature

	_ TokenStore = new(TokenStoreCookie)
	_ TokenStore = new(TokenStoreRedis)

	_ TokenContainer = new(TokenContainerJson)
	_ TokenContainer = new(TokenContainerJwt)
	_ TokenContainer = new(TokenContainerMsgpack)
	_ TokenContainer = new(TokenContainerSecretBox)

	_ TokenValidator = new(TokenValidatorExpire)
)

//

func (c *TokenConfig) Default() {
	if c.Container == nil {
		c.Container = &TokenContainerConfig{}
	}
	if c.Encoder == "" {
		c.Encoder = string(TokenEncodeDecoderTypeRaw)
	}
	if c.Validator == nil {
		c.Validator = &TokenValidatorConfig{}
	}
}

func (c *TokenConfig) Validate() error {
	switch TokenEncodeDecoderType(strings.ToLower(c.Encoder)) {
	case
		TokenEncodeDecoderTypeRaw,
		TokenEncodeDecoderTypeBase64:
	default:
		return errors.Errorf("unsupported encode decoder %q", c.Encoder)
	}
	return nil
}

//

func (c *TokenContainerConfig) Default() {
	if c.Type == "" {
		c.Type = string(TokenContainerTypeSecretBox)
	}

	if c.Type == string(TokenContainerTypeJson) && c.Json == nil {
		c.Json = &TokenContainerJsonConfig{}
	}
	if c.Type == string(TokenContainerTypeJwt) && c.Jwt == nil {
		c.Jwt = &TokenContainerJwtConfig{}
	}
	if c.Type == string(TokenContainerTypeMsgpack) && c.Msgpack == nil {
		c.Msgpack = &TokenContainerMsgpackConfig{}
	}
	if c.Type == string(TokenContainerTypeSecretBox) && c.SecretBox == nil {
		c.SecretBox = &TokenContainerSecretBoxConfig{}
	}
}

func (c *TokenContainerConfig) Validate() error {
	switch TokenContainerType(strings.ToLower(c.Type)) {
	case
		TokenContainerTypeJson,
		TokenContainerTypeJwt,
		TokenContainerTypeMsgpack,
		TokenContainerTypeSecretBox:
	default:
		return errors.Errorf("unsupported container type %q", c.Type)
	}
	return nil
}

//

func (c *TokenValidatorConfig) Default() {
	if c.Enable == nil {
		v := true
		c.Enable = &v
	}
	if c.Type == "" {
		c.Type = string(TokenValidatorTypeExpire)
	}
	// NOTE: Expirity is a mandatory behavior of the token
	// So, configuration should persist
	// Because we will calculate validBefore field based on this values
	if c.Expire == nil {
		c.Expire = &TokenValidatorExpireConfig{}
	}
}

func (c *TokenValidatorConfig) Validate() error {
	switch TokenValidatorType(strings.ToLower(c.Type)) {
	case
		TokenValidatorTypeExpire:
	default:
		return errors.Errorf("unsupported validator type %q", c.Type)
	}
	return nil
}

func (c *TokenValidatorExpireConfig) Default() {
	if c.MaxAge == nil {
		dur := 24 * time.Hour
		c.MaxAge = &dur
	}
	if c.TimeDrift == nil {
		dur := 30 * time.Second
		c.TimeDrift = &dur
	}
}

func (c *TokenValidatorExpireConfig) Validate() error {
	if *c.MaxAge <= 0 {
		return errors.New("max-age should be larger than zero")
	}
	if *c.TimeDrift < 0 {
		return errors.New("time-drift should be positive")
	}
	return nil
}

func (v *TokenValidatorExpire) Validate(t *Token) error {
	now := time.Now()

	if now.Before(t.Header.ValidAfter) {
		switch { // TODO: log clock skew? should have some sort of time based flag to prevent log flooding (log every 10 minutes or something)
		case now.Add(*v.Config.TimeDrift).After(t.Header.ValidAfter):
		default:
			return errors.Errorf(
				"token validity period has not started yet, valid after %q, but current time %q",
				t.Header.ValidAfter,
				now,
			)
		}
	}

	if now.After(t.Header.ValidBefore) {
		switch { // TODO: log clock skew? should have some sort of time based flag to prevent log flooding (log every 10 minutes or something)
		case now.Add(-*v.Config.TimeDrift).Before(t.Header.ValidBefore):
		default:
			return errors.Errorf(
				"token expired, valid before %q, but current time %q",
				t.Header.ValidBefore,
				now,
			)
		}
	}

	return nil
}

func NewTokenValidator(c *TokenValidatorConfig) TokenValidator {
	switch TokenValidatorType(strings.ToLower(c.Type)) {
	case TokenValidatorTypeExpire:
		return NewTokenValidatorExpire(c.Expire)
	default:
		panic(errors.Errorf("unsupported validator type %q", c.Type))
	}
}

func NewTokenValidatorExpire(c *TokenValidatorExpireConfig) *TokenValidatorExpire {
	return &TokenValidatorExpire{
		Config: c,
	}
}

//

func (c *TokenContainerJwtConfig) Validate() error {
	if c.Key != "" && c.KeyFile != "" {
		return errors.New("either key or key-file must be defined, not both")
	}
	if c.Key == "" && c.KeyFile == "" {
		return errors.New("either key or key-file must be defined")
	}
	if len(c.key) == 0 {
		return errors.New("key length should be greater than zero")
	}
	return nil
}

func (c *TokenContainerJwtConfig) Expand() error {
	var err error
	if c.KeyFile != "" {
		c.key, err = ioutil.ReadFile(c.KeyFile)
		if err != nil {
			return errors.Wrapf(err, "failed to load key-file: %q", c.KeyFile)
		}
	} else {
		c.key = []byte(c.Key)
	}
	return nil
}

//

func (c *TokenContainerSecretBoxConfig) Default() {
	if c.Container == nil {
		c.Container = &TokenContainerConfig{}
	}
	if c.Container.Type == "" {
		c.Container.Type = string(TokenContainerTypeMsgpack)
	}
}

func (c *TokenContainerSecretBoxConfig) Validate() error {
	if c.Key != "" && c.KeyFile != "" {
		return errors.New("either key or key-file must be defined, not both")
	}
	if c.Key == "" && c.KeyFile == "" {
		return errors.New("either key or key-file must be defined")
	}

	var emptyKey crypto.SecretBoxKey
	if bytes.Equal(c.key[:], emptyKey[:]) {
		return errors.Errorf("key be %d non-zero bytes", crypto.SecretBoxKeySize)
	}
	return nil
}

func (c *TokenContainerSecretBoxConfig) Expand() error {
	var (
		err error
		key []byte
	)
	if c.KeyFile != "" {
		key, err = ioutil.ReadFile(c.KeyFile)
		if err != nil {
			return errors.Wrapf(err, "failed to load key-file: %q", c.KeyFile)
		}
	} else {
		key = []byte(c.Key)
	}
	copy(c.key[:], key)
	return nil
}

//

func (s *Token) Seqno() uint { return s.seqno }

func (s *Token) Get(key string) (interface{}, bool) {
	v, ok := s.Payload[key]
	return v, ok
}

func (s *Token) MustGet(key string) interface{} {
	v, ok := s.Get(key)
	if !ok {
		panic(errors.Errorf("no key %q found", key))
	}
	return v
}

func (s *Token) GetBool(key string) (bool, bool) {
	v, ok := s.Payload[key]
	if ok {
		return v.(bool), ok
	}
	return false, false
}

func (s *Token) MustGetBool(key string) bool {
	return s.MustGet(key).(bool)
}

func (s *Token) GetInt(key string) (int, bool) {
	v, ok := s.Payload[key]
	if ok {
		return v.(int), ok
	}
	return 0, false
}

func (s *Token) MustGetInt(key string) int {
	return s.MustGet(key).(int)
}

func (s *Token) GetUint(key string) (uint, bool) {
	v, ok := s.Payload[key]
	if ok {
		return v.(uint), ok
	}
	return 0, false
}

func (s *Token) MustGetUint(key string) uint {
	return s.MustGet(key).(uint)
}

func (s *Token) GetString(key string) (string, bool) {
	v, ok := s.Payload[key]
	if ok {
		return v.(string), ok
	}
	return "", false
}

func (s *Token) MustGetString(key string) string {
	return s.MustGet(key).(string)
}

func (s *Token) Set(key string, value interface{}) {
	s.Payload[key] = value
	s.seqno++
}

func (s *Token) Del(key string) {
	_, ok := s.Payload[key]
	if ok {
		delete(s.Payload, key)
		s.seqno++
	}
}

//

func NewToken(c *TokenConfig) *Token {
	now := time.Now()
	return &Token{
		seqno: 0,
		Header: TokenHeader{
			ValidAfter:  now,
			ValidBefore: now.Add(*c.Validator.Expire.MaxAge),
		},
		Payload: TokenPayload{},
	}
}

func RequestTokenGet(c *TokenConfig, r *Request) *Token {
	ctxToken := r.Context().Value(ContextKeyToken)
	if ctxToken != nil {
		return ctxToken.(*Token)
	}

	return NewToken(c)
}

func RequestTokenSet(r *Request, s *Token) *Request {
	return r.WithContext(context.WithValue(r.Context(), ContextKeyToken, s))
}

//

func (c *TokenStoreConfig) Default() {
	if c.Type == string(TokenStoreTypeCookie) && c.Cookie == nil {
		c.Cookie = &TokenStoreCookieConfig{}
	}
	if c.Type == string(TokenStoreTypeRedis) && c.Redis == nil {
		c.Redis = &TokenStoreRedisConfig{}
	}
}

func (c *TokenStoreCookieConfig) Default() {
	if c.Name == "" {
		c.Name = fmt.Sprintf(
			"_%s",
			crypto.Sha1("gdk token cookie")[:8],
		)
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.Secure == nil {
		b := false
		c.Secure = &b
	}
	if c.HttpOnly == nil {
		b := true
		c.HttpOnly = &b
	}
	if c.SameSite == "" {
		c.SameSite = CookieSameSiteModesString[CookieSameSiteDefaultMode]
	}
}

func (c *TokenStoreCookieConfig) Validate() error {
	if _, ok := CookieSameSiteModes[c.SameSite]; !ok {
		available := make([]string, len(CookieSameSiteModes))
		n := 0
		for k := range CookieSameSiteModes {
			available[n] = k
			n++
		}
		sort.Strings(available)

		return errors.Errorf(
			"unexpected same-site value %q, expected one of: %q",
			c.SameSite, available,
		)
	}

	return nil
}

func (c *TokenStoreCookieConfig) Cookie() *Cookie {
	cookie := &Cookie{
		Name:     c.Name,
		Path:     c.Path,
		Domain:   c.Domain,
		Secure:   *c.Secure,
		HttpOnly: *c.HttpOnly,
		SameSite: CookieSameSiteModes[strings.ToLower(c.SameSite)],
	}
	if c.MaxAge != nil {
		cookie.MaxAge = int(*c.MaxAge / time.Second)
		cookie.Expires = time.Now().Add(*c.MaxAge)
	}
	return cookie
}

func (s *TokenStoreCookie) Id(r *Request) ([]byte, error) {
	cookie, err := CookieGet(r, s.Config.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get cookie from request")
	}
	return []byte(cookie.Value), nil
}

func (s *TokenStoreCookie) Save(t *Token) ([]byte, error) {
	id, err := s.Container.Encode(t)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode container")
	}

	if s.EncodeDecoder != nil {
		id, err = s.EncodeDecoder.Encode(id)
		if err != nil {
			return nil, errors.Wrap(err, "failed to encode cookie value")
		}
	}
	return id, nil
}

func (s *TokenStoreCookie) RequestSave(w ResponseWriter, r *Request, t *Token) ([]byte, error) {
	id, err := s.Save(t)
	if err != nil {
		return nil, err
	}

	cookie := s.Config.Cookie()
	cookie.Value = string(id)
	CookieSet(w, cookie)
	return id, nil
}

func (s *TokenStoreCookie) Load(id []byte) (*Token, error) {
	var err error
	if s.EncodeDecoder != nil {
		id, err = s.EncodeDecoder.Decode(id)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode cookie value")
		}
	}

	t, err := s.Container.Decode(id)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode container")
	}
	return t, nil
}

func (s *TokenStoreCookie) RequestLoad(r *Request) (*Token, error) {
	id, err := s.Id(r)
	if err != nil {
		return nil, err
	}
	t, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *TokenStoreCookie) Drop(id []byte) error {
	// NOTE: nothing to do, buf is the session itself, we should only drop the cookie
	// which is handled by RequestDrop(...)
	return nil
}

func (s *TokenStoreCookie) RequestDrop(w ResponseWriter, r *Request) error {
	cookie := s.Config.Cookie()
	cookie.Expires = time.Time{} // 0001-01-01 00:00:00 +0000 UTC

	CookieSet(w, cookie)
	return nil
}

func NewTokenStoreCookie(c *TokenStoreCookieConfig, cont TokenContainer, enc TokenEncodeDecoder) *TokenStoreCookie {
	return &TokenStoreCookie{
		Config:        c,
		Container:     cont,
		EncodeDecoder: enc,
	}
}

//

func (c *TokenStoreRedisConfig) Default() {
	if c.Address == "" {
		c.Address = "127.0.0.1:6379"
	}
	if c.Cookie == nil {
		c.Cookie = &TokenStoreCookieConfig{}
	}
}

func (c *TokenStoreRedisConfig) Validate() error {
	if c.Password != "" && c.PasswordFile != "" {
		return errors.New("either password or password-file should be specified, not both")
	}

	return nil
}

func (c *TokenStoreRedisConfig) Expand() error {
	if c.PasswordFile != "" {
		passwordBytes, err := ioutil.ReadFile(c.PasswordFile)
		if err != nil {
			return err
		}
		c.password = string(passwordBytes)
	} else {
		c.password = c.Password
	}
	return nil
}

func (s *TokenStoreRedis) Id(r *Request) ([]byte, error) {
	cookie, err := CookieGet(r, s.Config.Cookie.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get cookie from request")
	}
	return []byte(cookie.Value), nil
}

func (s *TokenStoreRedis) Save(t *Token) ([]byte, error) {
	var id string
	rawId, ok := t.Get(string(TokenPayloadKeyId))
	if ok {
		id = rawId.(string)
	} else {
		id = uuid.NewString()
		t.Set(string(TokenPayloadKeyId), id)
	}

	buf, err := s.Container.Encode(t)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode token container")
	}
	if s.EncodeDecoder != nil {
		buf, err = s.EncodeDecoder.Encode(buf)
		if err != nil {
			return nil, errors.Wrap(err, "failed to encode token value")
		}
	}

	err = s.Store.Set(id, buf)
	if err != nil {
		return nil, err
	}

	return []byte(id), nil
}

func (s *TokenStoreRedis) RequestSave(w ResponseWriter, r *Request, t *Token) ([]byte, error) {
	id, err := s.Save(t)
	if err != nil {
		return nil, err
	}

	cookie := s.Config.Cookie.Cookie()
	cookie.Value = string(id)
	CookieSet(w, cookie)

	return id, nil
}

func (s *TokenStoreRedis) Load(id []byte) (*Token, error) {
	var (
		buf []byte
		err error
	)

	ok, err := s.Store.Get(string(id), &buf)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.Errorf("no key with id %q", string(id))
	}

	if s.EncodeDecoder != nil {
		buf, err = s.EncodeDecoder.Decode(buf)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode token value")
		}
	}
	t, err := s.Container.Decode(buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode token container")
	}

	return t, nil
}

func (s *TokenStoreRedis) RequestLoad(r *Request) (*Token, error) {
	id, err := s.Id(r)
	if err != nil {
		return nil, err
	}
	t, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *TokenStoreRedis) Drop(id []byte) error {
	return s.Store.Delete(string(id))
}

func (s *TokenStoreRedis) RequestDrop(w ResponseWriter, r *Request) error {
	id, err := s.Id(r)
	if err != nil {
		return err
	}

	cookie := s.Config.Cookie.Cookie()
	cookie.MaxAge = 0
	cookie.Expires = time.Time{} // 0001-01-01 00:00:00 +0000 UTC
	CookieSet(w, cookie)

	return s.Drop(id)
}

func NewTokenStoreRedis(c *TokenStoreRedisConfig, cont TokenContainer, enc TokenEncodeDecoder) *TokenStoreRedis {
	options := redis.Options{
		Address:  c.Address,
		Password: c.password,
		DB:       c.Db,
	}
	s, err := redis.NewClient(options)
	if err != nil {
		panic(err)
	}

	return &TokenStoreRedis{
		Config:        c,
		Container:     cont,
		EncodeDecoder: enc,
		Store:         s,
	}
}

//

func NewTokenStore(c *TokenStoreConfig, cont TokenContainer, enc TokenEncodeDecoder) (TokenStore, error) {
	switch strings.ToLower(c.Type) {
	case string(TokenStoreTypeCookie):
		return NewTokenStoreCookie(c.Cookie, cont, enc), nil
	case string(TokenStoreTypeRedis):
		return NewTokenStoreRedis(c.Redis, cont, enc), nil
	default:
		return nil, errors.Errorf("unsupported store type: %q", c.Type)
	}
}

//

func (c *TokenContainerJson) Encode(s *Token) ([]byte, error) {
	return json.Marshal(s)
}
func (c *TokenContainerJson) Decode(buf []byte) (*Token, error) {
	s := &Token{}
	err := json.Unmarshal(buf, s)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func NewTokenContainerJson(c *TokenContainerJsonConfig) *TokenContainerJson {
	return &TokenContainerJson{
		Config: c,
	}
}

//

func (c *TokenContainerJwt) Encode(s *Token) ([]byte, error) {
	token, err := c.Builder.Build(&TokenJwt{
		RegisteredClaims: jwt.RegisteredClaims{
			NotBefore: &jwt.NumericDate{Time: s.Header.ValidAfter},
			IssuedAt:  &jwt.NumericDate{Time: s.Header.ValidAfter},
			ExpiresAt: &jwt.NumericDate{Time: s.Header.ValidBefore},
		},
		Payload: s.Payload,
	})
	if err != nil {
		return nil, err
	}

	return token.Bytes(), nil
}
func (c *TokenContainerJwt) Decode(buf []byte) (*Token, error) {
	j := &TokenJwt{}
	err := jwt.ParseClaims(buf, c.Verifier, j)
	if err != nil {
		return nil, err
	}
	s := &Token{}
	s.Header = TokenHeader{
		ValidAfter:  j.RegisteredClaims.IssuedAt.Time,
		ValidBefore: j.RegisteredClaims.ExpiresAt.Time,
	}
	s.Payload = j.Payload
	return s, nil
}
func NewTokenContainerJwt(c *TokenContainerJwtConfig) *TokenContainerJwt {
	var (
		s   jwt.Signer
		v   jwt.Verifier
		err error
	)

	algo := TokenJwtAlgorithms[strings.ToLower(c.Algorithm)]
	switch algo {
	case TokenJwtAlgorithmHS256, TokenJwtAlgorithmHS384, TokenJwtAlgorithmHS512:
		s, err = jwt.NewSignerHS(algo, c.key)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierHS(algo, c.key)
		if err != nil {
			panic(err)
		}
	case TokenJwtAlgorithmES256, TokenJwtAlgorithmES384, TokenJwtAlgorithmES512:
		block, _ := pem.Decode(c.key)
		ecdsaPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		ecdsaPublicKey := ecdsaPrivateKey.Public().(*ecdsa.PublicKey)

		s, err = jwt.NewSignerES(algo, ecdsaPrivateKey)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierES(algo, ecdsaPublicKey)
		if err != nil {
			panic(err)
		}
	case TokenJwtAlgorithmPS256, TokenJwtAlgorithmPS384, TokenJwtAlgorithmPS512:
		block, _ := pem.Decode(c.key)
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			panic(errors.Errorf("private key is not *rsa.PrivateKey, it is %T", privateKey))
		}
		rsaPublicKey := rsaPrivateKey.Public().(*rsa.PublicKey)

		s, err = jwt.NewSignerPS(algo, rsaPrivateKey)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierPS(algo, rsaPublicKey)
		if err != nil {
			panic(err)
		}
	case TokenJwtAlgorithmRS256, TokenJwtAlgorithmRS384, TokenJwtAlgorithmRS512:
		block, _ := pem.Decode(c.key)
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			panic(errors.Errorf("private key is not *rsa.PrivateKey, it is %T", privateKey))
		}
		rsaPublicKey := rsaPrivateKey.Public().(*rsa.PublicKey)

		s, err = jwt.NewSignerRS(algo, rsaPrivateKey)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierRS(algo, rsaPublicKey)
		if err != nil {
			panic(err)
		}
	case TokenJwtAlgorithmEdDSA:
		block, _ := pem.Decode(c.key)
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			panic(errors.Errorf("private key is not ed25519.PrivateKey, it is %T", privateKey))
		}
		ed25519PublicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)

		s, err = jwt.NewSignerEdDSA(ed25519PrivateKey)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierEdDSA(ed25519PublicKey)
		if err != nil {
			panic(err)
		}
	default:
		panic(errors.Errorf("unsupported JWT marshaling algorithm %q", c.Algorithm))
	}

	return &TokenContainerJwt{
		Config:   c,
		Builder:  jwt.NewBuilder(s),
		Verifier: v,
	}
}

//

func (c *TokenContainerMsgpack) Encode(s *Token) ([]byte, error) {
	return msgpack.Marshal(s)
}
func (c *TokenContainerMsgpack) Decode(buf []byte) (*Token, error) {
	s := &Token{}
	err := msgpack.Unmarshal(buf, s)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func NewTokenContainerMsgpack(c *TokenContainerMsgpackConfig) *TokenContainerMsgpack {
	return &TokenContainerMsgpack{
		Config: c,
	}
}

//

func (c *TokenContainerSecretBox) Encode(s *Token) ([]byte, error) {
	tokenBytes, err := c.Container.Encode(s)
	if err != nil {
		return nil, err
	}

	nonce, err := c.SecretBox.Nonce()
	if err != nil {
		return nil, err
	}
	return c.SecretBox.SealBase64(nonce, tokenBytes), nil
}
func (c *TokenContainerSecretBox) Decode(buf []byte) (*Token, error) {
	buf, err := c.SecretBox.OpenBase64(buf)
	if err != nil {
		return nil, err
	}

	return c.Container.Decode(buf)
}
func NewTokenContainerSecretBox(c *TokenContainerSecretBoxConfig) *TokenContainerSecretBox {
	return &TokenContainerSecretBox{
		Config:    c,
		Container: NewTokenContainer(c.Container),
		SecretBox: crypto.NewSecretBox(crypto.DefaultRand, &c.key),
	}
}

//

func NewTokenContainer(c *TokenContainerConfig) TokenContainer {
	switch strings.ToLower(c.Type) {
	case string(TokenContainerTypeJson):
		return NewTokenContainerJson(c.Json)
	case string(TokenContainerTypeJwt):
		return NewTokenContainerJwt(c.Jwt)
	case string(TokenContainerTypeMsgpack):
		return NewTokenContainerMsgpack(c.Msgpack)
	case string(TokenContainerTypeSecretBox):
		return NewTokenContainerSecretBox(c.SecretBox)
	default:
		panic(errors.Errorf("unsupported token container type: %q", c.Type))
	}
}

//

func NewTokenEncodeDecoder(t string) TokenEncodeDecoder {
	var e encoding.EncodeDecoder
	switch TokenEncodeDecoderType(strings.ToLower(t)) {
	case TokenEncodeDecoderTypeRaw:
	case TokenEncodeDecoderTypeBase64:
		e = encoding.NewEncodeDecoderBase64()
	default:
		panic(errors.Errorf("unsupported encode decoder type %q", t))
	}
	return e
}
