package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"strings"
	"time"

	jwt "github.com/cristalhq/jwt/v4"
	msgpack "github.com/vmihailenco/msgpack/v5"

	"github.com/corpix/gdk/encoding"
	"github.com/corpix/gdk/errors"
)

type (
	TokenConfig struct {
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
		key       SecretBoxKey
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
		SecretBox *SecretBox
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

	var emptyKey SecretBoxKey
	if bytes.Equal(c.key[:], emptyKey[:]) {
		return errors.Errorf("key be %d non-zero bytes", SecretBoxKeySize)
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
		SecretBox: NewSecretBox(DefaultRand, &c.key),
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
