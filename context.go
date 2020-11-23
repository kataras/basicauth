package basicauth

import (
	"context"
	"net/http"
)

// key is the type used for any items added to the request context.
type key uint8

const (
	// userContextKey is the key for the authenticated user.
	userContextKey key = iota
	// logoutFuncContextKey is the key for the user logout function.
	logoutFuncContextKey
)

type logoutFunc func(*http.Request) *http.Request

// GetUser returns the current authenticated User.
// If no custom user was set then it should be a type of *basicauth.SimpleUser.
func GetUser(r *http.Request) interface{} {
	return r.Context().Value(userContextKey)
}

// Logout deletes the authenticated user entry from the backend.
// The client should login again on the next request.
func Logout(r *http.Request) *http.Request {
	if fn, ok := r.Context().Value(logoutFuncContextKey).(logoutFunc); ok {
		r = fn(r)
	}

	return r
}

// newContext returns a new Context with specific basicauth values.
func newContext(ctx context.Context, user interface{}, logoutFn logoutFunc) context.Context {
	parent := context.WithValue(ctx, userContextKey, user)
	return context.WithValue(parent, logoutFuncContextKey, logoutFn)
}

func clearContext(ctx context.Context) context.Context {
	return newContext(ctx, nil, nil)
}
