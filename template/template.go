package template

import (
	"html/template"

	sprig "github.com/Masterminds/sprig/v3"
	"github.com/corpix/gdk/di"
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

	Option func(*Template)
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

func WithProvide(cont *di.Container) Option {
	return func(t *Template) {
		di.MustProvide(cont, func() *Template { return t })
	}
}

func WithInvoke(cont *di.Container, f di.Function) Option {
	return func(t *Template) {
		di.MustInvoke(cont, f)
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
