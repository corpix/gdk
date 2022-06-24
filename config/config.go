package config

import (
	"github.com/corpix/revip"

	"github.com/corpix/gdk/log"
)

type (
	Config              = revip.Config
	Defaultable         = revip.Defaultable
	ErrFileNotFound     = revip.ErrFileNotFound
	ErrMarshal          = revip.ErrMarshal
	ErrPathNotFound     = revip.ErrPathNotFound
	ErrPostprocess      = revip.ErrPostprocess
	ErrUnexpectedKind   = revip.ErrUnexpectedKind
	ErrUnexpectedScheme = revip.ErrUnexpectedScheme
	ErrUnmarshal        = revip.ErrUnmarshal
	Expandable          = revip.Expandable
	Marshaler           = revip.Marshaler
	Option              = revip.Option
	Container           = revip.Container
	Unmarshaler         = revip.Unmarshaler
	Validatable         = revip.Validatable
)

//

type BaseConfig struct {
	Log *log.Config `yaml:"log"`
}

func (c *BaseConfig) Default() {
	if c.Log == nil {
		c.Log = &log.Config{}
	}
}

//

const (
	PathDelimiter = revip.PathDelimiter
)

var (
	FromEnviron    = revip.FromEnviron
	FromFile       = revip.FromFile
	FromReader     = revip.FromReader
	FromURL        = revip.FromURL
	Load           = revip.Load
	New            = revip.New
	Postprocess    = revip.Postprocess
	ToFile         = revip.ToFile
	ToURL          = revip.ToURL
	ToWriter       = revip.ToWriter
	WithDefaults   = revip.WithDefaults
	WithExpansion  = revip.WithExpansion
	WithValidation = revip.WithValidation

	JsonMarshaler   = revip.JsonMarshaler
	JsonUnmarshaler = revip.JsonUnmarshaler
	YamlMarshaler   = revip.YamlMarshaler
	YamlUnmarshaler = revip.YamlUnmarshaler
	TomlMarshaler   = revip.TomlMarshaler
	TomlUnmarshaler = revip.TomlUnmarshaler
)
