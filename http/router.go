package http

import (
	"github.com/gorilla/mux"
)

type (
	Router         = mux.Router
	Route          = mux.Route
	RouteMatch     = mux.RouteMatch
	MiddlewareFunc = mux.MiddlewareFunc
)

var (
	SetURLVars   = mux.SetURLVars
	GetURLVars   = mux.Vars
	CurrentRoute = mux.CurrentRoute
	NewRouter    = mux.NewRouter
)
