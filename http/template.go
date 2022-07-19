package http

import (
	"github.com/corpix/gdk/template"
)

const (
	TemplateContextKeyRequest template.ContextKey = "request"
	TemplateContextKeySession template.ContextKey = "session"
)

func NewTemplateContext(r *Request) template.Context {
	return template.NewContext().
		With(TemplateContextKeyRequest, r)
}
