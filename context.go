package basicauth

import (
	"context"
	"net/http"
	"time"
)

// contextKey is the type of the single key the middleware stores in the request context.
type contextKey struct{}

type logoutFunc func(*http.Request) *http.Request

// authInfo carries everything the middleware attaches to an authenticated request.
// Storing one value instead of one per field keeps the context chain short:
// one allocation per request rather than one per stored field.
type authInfo struct {
	user         any
	authorizedAt time.Time
	logout       logoutFunc
}

func getAuthInfo(r *http.Request) *authInfo {
	info, _ := r.Context().Value(contextKey{}).(*authInfo)
	return info
}

// GetUser returns the authenticated user stored in the request by a BasicAuth middleware,
// as the type U that its Options.Allow returned.
// It reports false when the request was not authenticated or when the stored user is not a U.
//
// Prefer the BasicAuth.User method when the middleware instance is at hand,
// as it needs no explicit type argument. GetUser exists for handlers in other packages.
//
// Usage:
//
//	user, ok := basicauth.GetUser[MyUser](r)
func GetUser[U any](r *http.Request) (U, bool) {
	if info := getAuthInfo(r); info != nil {
		u, ok := info.user.(U)
		return u, ok
	}

	var zero U
	return zero, false
}

// AuthorizedAt returns the time the request's credentials were first accepted
// by a BasicAuth middleware, as implied by its Options.MaxAge entry.
// It reports false when the request was not authenticated or when MaxAge is zero,
// as the middleware keeps no per-login time without an expiration.
//
// Usage:
//
//	at, ok := basicauth.AuthorizedAt(r)
func AuthorizedAt(r *http.Request) (time.Time, bool) {
	if info := getAuthInfo(r); info != nil && !info.authorizedAt.IsZero() {
		return info.authorizedAt, true
	}

	return time.Time{}, false
}

// Logout deletes the authenticated user entry from the backend.
// The client should login again on the next request.
// See BasicAuth.Logout and Options.OnLogoutClearContext for details.
func Logout(r *http.Request) *http.Request {
	if info := getAuthInfo(r); info != nil && info.logout != nil {
		r = info.logout(r)
	}

	return r
}

// newContext returns a new Context with specific basicauth values.
func newContext(ctx context.Context, user any, authorizedAt time.Time, logoutFn logoutFunc) context.Context {
	return context.WithValue(ctx, contextKey{}, &authInfo{user: user, authorizedAt: authorizedAt, logout: logoutFn})
}

// clearContext returns a Context whose basicauth values are removed.
func clearContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKey{}, (*authInfo)(nil))
}
