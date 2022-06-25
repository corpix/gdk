package http

import (
	"github.com/gorilla/mux"
)

type (
	Router         = mux.Router
	RouterOption   func(*Router)
	Route          = mux.Route
	RouteMatch     = mux.RouteMatch
	MiddlewareFunc = mux.MiddlewareFunc
)

var (
	SetURLVars   = mux.SetURLVars
	GetURLVars   = mux.Vars
	CurrentRoute = mux.CurrentRoute
)

func NewRouter(options ...RouterOption) *Router {
	r := mux.NewRouter()
	for _, option := range options {
		option(r)
	}
	return r
}
