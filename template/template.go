package template

import (
	"html/template"

	sprig "github.com/Masterminds/sprig/v3"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
)

type (
	CSS       = template.CSS
	Error     = template.Error
	ErrorCode = template.ErrorCode
	FuncMap   = template.FuncMap
	HTML      = template.HTML
	HTMLAttr  = template.HTMLAttr
	JS        = template.JS
	JSStr     = template.JSStr
	Srcset    = template.Srcset
	Template  = template.Template
	URL       = template.URL

	Option     func(*Template)
	Context    map[string]interface{}
	ContextKey string

	Config struct {
		Templates map[string]string `yaml:"templates"`
	}
)

var (
	HTMLEscape       = template.HTMLEscape
	HTMLEscapeString = template.HTMLEscapeString
	HTMLEscaper      = template.HTMLEscaper
	IsTrue           = template.IsTrue
	JSEscape         = template.JSEscape
	JSEscapeString   = template.JSEscapeString
	JSEscaper        = template.JSEscaper
	URLQueryEscaper  = template.URLQueryEscaper
	Must             = template.Must
	ParseFS          = template.ParseFS
	ParseFiles       = template.ParseFiles
	ParseGlob        = template.ParseGlob
)

func (c Context) With(key ContextKey, value interface{}) Context {
	c[string(key)] = value
	return c
}

func NewContext() Context { return Context{} }

//

func WithProvide(cont *di.Container) Option {
	return func(t *Template) {
		di.MustProvide(cont, func() *Template { return t })
	}
}

func WithInvoke(cont *di.Container, f di.Function) Option {
	return func(t *Template) { di.MustInvoke(cont, f) }
}

func WithConfig(c *Config) Option {
	return func(t *Template) {
		for name, data := range c.Templates {
			_, err := t.New(name).Parse(data)
			if err != nil {
				panic(errors.Wrap(err, "failed to parse"))
			}
		}
	}
}

func WithFuncMap(fm ...FuncMap) Option {
	return func(t *Template) {
		for _, f := range fm {
			t.Funcs(f)
		}
	}
}

func Parse(name string, data string) (*Template, error) {
	return New(name).Parse(data)
}

func New(name string, options ...Option) *Template {
	t := template.New(name).Funcs(sprig.FuncMap())
	for _, option := range options {
		option(t)
	}
	return t
}
