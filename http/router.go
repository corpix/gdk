package http

import (
	"github.com/gorilla/mux"
)

type (
	Router         = mux.Router
	RouteWalkFn    = mux.WalkFunc
	Route          = mux.Route
	RouteMatch     = mux.RouteMatch
	MiddlewareFunc = mux.MiddlewareFunc
)

var (
	SetURLVars   = mux.SetURLVars
	GetURLVars   = mux.Vars
	CurrentRoute = mux.CurrentRoute
)

func NewRouter(c *Config) *Router {
	r := mux.NewRouter()
	if c.Prefix != "" {
		r = r.PathPrefix(c.Prefix).Subrouter()
	}
	return r
}
