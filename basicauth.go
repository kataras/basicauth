package basicauth

import (
	"context"
	"log"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultRealm is the default realm directive value on Default and Load functions.
	DefaultRealm = "Authorization Required"
	// DefaultMaxTriesCookie is the default cookie name to store the
	// current amount of login failures when MaxTries > 0.
	DefaultMaxTriesCookie = "basicmaxtries"
	// DefaultCookieMaxAge is the default cookie max age on MaxTries,
	// when the Options.MaxAge is zero.
	DefaultCookieMaxAge = time.Hour
)

// cookieExpireDelete may be set on Cookie.Expire for expiring the given cookie.
// Note that the MaxAge is set but we set Expires field in order to support very old browsers too.
var cookieExpireDelete = time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)

const (
	authenticateHeaderKey       = "WWW-Authenticate"
	proxyAuthenticateHeaderKey  = "Proxy-Authenticate"
	authorizationHeaderKey      = "Authorization"
	proxyAuthorizationHeaderKey = "Proxy-Authorization"
)

type (
	// Map is just a type alias of the map[string]any.
	// It is the user type of users loaded from a file through Load and AllowUsersFile[Map].
	Map = map[string]any
	// Middleware is just a type alias of func(http.Handler) http.Handler
	Middleware = func(http.Handler) http.Handler
)

// Func converts a Middleware of func(http.Handler) http.Handler
// to a func(HandlerFunc) http.HandlerFunc.
// Maybe useful for some third-party handlers chaining.
//
// Usage:
//
//	mux.HandleFunc("/", basicauth.Func(auth.Middleware())(index))
func Func(auth Middleware) func(http.HandlerFunc) http.HandlerFunc {
	return func(fn http.HandlerFunc) http.HandlerFunc {
		return auth(fn).ServeHTTP
	}
}

// HandlerFunc accepts a Middleware (http.Handler) http.Handler
// and a handler and returns a HandlerFunc.
// See the BasicAuth.HandlerFunc method for the shorter form.
//
// Usage:
//
//	mux.HandleFunc("/", basicauth.HandlerFunc(auth.Middleware(), index))
func HandlerFunc(auth Middleware, handlerFunc func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return auth(http.HandlerFunc(handlerFunc)).ServeHTTP
}

// AuthFunc accepts the current request and the username and password user inputs
// and it should return the user value of type U and report whether the login succeeded or not.
// Look the Options.Allow field.
//
// Default implementations are:
// AllowUsers, AllowUsersMap and AllowUsersFile functions.
type AuthFunc[U any] func(r *http.Request, username, password string) (U, bool)

// ErrorHandler should handle the given request credentials failure.
// See Options.ErrorHandler and DefaultErrorHandler for details.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Options holds the necessary information that the BasicAuth instance needs to perform.
// The only required value is the Allow field.
// The type parameter U is the type of the authenticated user that Allow returns
// and that BasicAuth.User (or GetUser) gives back to the handlers.
//
// Usage:
//
//	opts := Options[MyUser]{ ... }
//	auth := New(opts)
type Options[U any] struct {
	// Realm directive, read http://tools.ietf.org/html/rfc2617#section-1.2 for details.
	// E.g. "Authorization Required".
	Realm string
	// In the case of proxies, the challenging status code is 407 (Proxy Authentication Required),
	// the Proxy-Authenticate response header contains at least one challenge applicable to the proxy,
	// and the Proxy-Authorization request header is used for providing the credentials to the proxy server.
	//
	// Proxy should be used to gain access to a resource behind a proxy server.
	// It authenticates the request to the proxy server, allowing it to transmit the request further.
	Proxy bool
	// If set to true then any request that is not served over TLS
	// and HTTP/2 is immediately dropped with a 505 status code
	// (StatusHTTPVersionNotSupported) response. Plain HTTP and HTTPS/1.1
	// requests are both rejected.
	//
	// Defaults to false.
	HTTPSOnly bool
	// Allow is the only one required field for the Options type.
	// Can be customized to validate a username and password combination
	// and return a user object, e.g. fetch from database.
	//
	// There are three builtin implementations, AllowUsers, AllowUsersMap and AllowUsersFile.
	// All of them decode a static list of users and compare it with the user input (see the BCRYPT option too).
	// Usage:
	//  - Allow: AllowUsers([]MyUser{...}, [BCRYPT])
	//  - Allow: AllowUsersMap(map[string]string{"username": "password"}, [BCRYPT])
	//  - Allow: AllowUsersFile[Map]("users.yml", [BCRYPT])
	// Look the user.go source file for details.
	Allow AuthFunc[U]
	// MaxAge sets expiration duration for the in-memory credentials map.
	// By default an old map entry will be removed when the user visits a page.
	// In order to remove old entries automatically please take a look at the `GC` option too.
	//
	// Usage:
	//  MaxAge: 30 * time.Minute
	MaxAge time.Duration
	// If greater than zero then the server will send 403 forbidden status code after
	// MaxTries amount of sign in failures (see MaxTriesCookie).
	// Note that the client can modify the cookie and its value,
	// do NOT depend for any type of custom domain logic based on this field.
	// By default the server will re-ask for credentials on invalid credentials, each time.
	MaxTries int
	// MaxTriesCookie is the cookie name the middleware uses to
	// store the failures amount on the client side.
	// The lifetime of the cookie is the same as the configured MaxAge or one hour,
	// therefore a forbidden client can request for authentication again after expiration.
	//
	// You can always set custom logic on the Allow field as you have access to the current request instance.
	//
	// Defaults to "basicmaxtries".
	// The MaxTries should be set to greater than zero.
	MaxTriesCookie string
	// ErrorHandler handles the given request credentials failure.
	// E.g  when the client tried to access a protected resource
	// with empty or invalid or expired credentials or
	// when Allow returned false and MaxTries consumed.
	//
	// Defaults to the DefaultErrorHandler, do not modify if you don't need to.
	ErrorHandler ErrorHandler
	// ErrorLogger if not nil then it logs any credentials failure errors
	// that are going to be sent to the client. Set it on debug development state.
	// Usage:
	//  ErrorLogger = log.New(os.Stderr, "", log.LstdFlags)
	//
	// Defaults to nil.
	ErrorLogger *log.Logger
	// GC automatically clears old entries every x duration.
	// Note that, by old entries we mean expired credentials therefore
	// the `MaxAge` option should be already set,
	// if it's not then all entries will be removed on "every" duration.
	// The standard context can be used for the internal ticker cancelation, it can be nil.
	//
	// Usage:
	//  GC: basicauth.GC{Every: 2 * time.Hour}
	GC GC
	// OnLogoutClearContext will clear the context values stored by
	// the middleware when Logout is called.
	// This means that the User and GetUser will report false after a Logout call was made.
	//
	// Defaults to false.
	OnLogoutClearContext bool
}

// GC holds the context and the tick duration to clear expired stored credentials.
// See the Options.GC field.
type GC struct {
	Context context.Context
	Every   time.Duration
}

// BasicAuth implements the basic access authentication.
// It is a method for an HTTP client (e.g. a web browser)
// to provide a user name and password when making a request.
// Basic authentication implementation is the simplest technique
// for enforcing access controls to web resources because it does not require
// cookies, session identifiers, or login pages; rather,
// HTTP Basic authentication uses standard fields in the HTTP header.
//
// As the username and password are passed over the network as clear text
// the basic authentication scheme is not secure on plain HTTP communication.
// It is base64 encoded, but base64 is a reversible encoding.
// HTTPS/TLS should be used with basic authentication.
// Without these additional security enhancements,
// basic authentication should NOT be used to protect sensitive or valuable information.
//
// The type parameter U is the authenticated user type, see Options.
// Wrap a handler with the Wrap or HandlerFunc methods and read the user back
// inside the handlers with the User method.
//
// Read https://tools.ietf.org/html/rfc2617 and
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication for details.
type BasicAuth[U any] struct {
	opts Options[U]
	// built based on proxy field
	askCode             int
	authorizationHeader string
	authenticateHeader  string
	// built based on realm field.
	authenticateHeaderValue string

	// credentials stores the user expiration,
	// key = username:password, value = expiration time.
	// The zero time means the entry never expires (MaxAge == 0).
	credentials map[string]time.Time
	// protects the credentials concurrent access.
	mu sync.RWMutex
}

// New returns a new basic authentication middleware.
// Wrap an existing handler or the HTTP application's root router with its Wrap method.
//
// Example Code:
//
//	auth := basicauth.New(basicauth.Options[MyUser]{
//		Realm: basicauth.DefaultRealm,
//	    ErrorHandler: basicauth.DefaultErrorHandler,
//		MaxAge: 2 * time.Hour,
//		GC: basicauth.GC{
//			Every: 3 * time.Hour,
//		},
//		Allow: basicauth.AllowUsers(users),
//	})
//	mux := http.NewServeMux()
//	[...routes]
//	http.ListenAndServe(":8080", auth.Wrap(mux))
//
// Access the user in the route handler with:
//
//	user, ok := auth.User(r) // user is a MyUser.
//
// Look the BasicAuth type docs for more information.
func New[U any](opts Options[U]) *BasicAuth[U] {
	var (
		askCode                 = http.StatusUnauthorized
		authorizationHeader     = authorizationHeaderKey
		authenticateHeader      = authenticateHeaderKey
		authenticateHeaderValue = "Basic"
	)

	if opts.Allow == nil {
		panic("BasicAuth: Allow field is required")
	}

	if opts.Realm != "" {
		authenticateHeaderValue += " realm=" + strconv.Quote(opts.Realm)
	}

	if opts.Proxy {
		askCode = http.StatusProxyAuthRequired
		authenticateHeader = proxyAuthenticateHeaderKey
		authorizationHeader = proxyAuthorizationHeaderKey
	}

	if opts.MaxTries > 0 && opts.MaxTriesCookie == "" {
		opts.MaxTriesCookie = DefaultMaxTriesCookie
	}

	if opts.ErrorHandler == nil {
		opts.ErrorHandler = DefaultErrorHandler
	}

	b := &BasicAuth[U]{
		opts:                    opts,
		askCode:                 askCode,
		authorizationHeader:     authorizationHeader,
		authenticateHeader:      authenticateHeader,
		authenticateHeaderValue: authenticateHeaderValue,
		credentials:             make(map[string]time.Time),
	}

	if opts.GC.Every > 0 {
		go b.runGC(opts.GC.Context, opts.GC.Every)
	}

	return b
}

// Default returns a new basic authentication middleware
// based on a pre-defined username:password list.
// The authenticated user is a SimpleUser.
// For custom user types use New with AllowUsers or AllowUsersFile.
//
// Usage:
//
//	auth := Default(map[string]string{
//	  "admin": "admin",
//	  "john": "p@ss",
//	})
func Default(users map[string]string, userOpts ...UserAuthOption[SimpleUser]) *BasicAuth[SimpleUser] {
	return New(Options[SimpleUser]{
		Realm: DefaultRealm,
		Allow: AllowUsersMap(users, userOpts...),
	})
}

// Load same as Default but instead of a hard-coded user list it accepts
// a filename to load the users from. The authenticated user is a Map.
// For a typed user use New with AllowUsersFile[MyUser].
//
// Usage:
//
//	auth := Load("users.yml")
func Load(jsonOrYamlFilename string, userOpts ...UserAuthOption[Map]) *BasicAuth[Map] {
	return New(Options[Map]{
		Realm: DefaultRealm,
		Allow: AllowUsersFile[Map](jsonOrYamlFilename, userOpts...),
	})
}

// Wrap returns a handler that authenticates the request
// and calls "next" only when the client is allowed to continue.
//
// Usage:
//
//	http.ListenAndServe(":8080", auth.Wrap(mux))
func (b *BasicAuth[U]) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.serveHTTP(w, r, next)
	})
}

// HandlerFunc wraps a single route handler function.
//
// Usage:
//
//	mux.HandleFunc("/", auth.HandlerFunc(index))
func (b *BasicAuth[U]) HandlerFunc(handlerFunc func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return b.Wrap(http.HandlerFunc(handlerFunc)).ServeHTTP
}

// Middleware returns the Wrap method as a Middleware value,
// useful for third-party handler chains that accept func(http.Handler) http.Handler.
func (b *BasicAuth[U]) Middleware() Middleware {
	return b.Wrap
}

// User returns the authenticated user of the request as stored by this middleware.
// It reports false when the request did not pass through this middleware
// or when the user was cleared by Logout with Options.OnLogoutClearContext enabled.
func (b *BasicAuth[U]) User(r *http.Request) (U, bool) {
	return GetUser[U](r)
}

// Logout deletes the authenticated user entry from the backend.
// The client should login again on the next request.
// It returns the request to use from now on, which differs from the given one
// only when Options.OnLogoutClearContext is enabled.
func (b *BasicAuth[U]) Logout(r *http.Request) *http.Request {
	return b.logout(r)
}

func (b *BasicAuth[U]) getCurrentTries(r *http.Request) (tries int) {
	if cookie, err := r.Cookie(b.opts.MaxTriesCookie); err == nil {
		if v := cookie.Value; v != "" {
			tries, _ = strconv.Atoi(v)
		}
	}

	return
}

func (b *BasicAuth[U]) setCurrentTries(w http.ResponseWriter, tries int) {
	maxAge := b.opts.MaxAge
	if maxAge == 0 {
		maxAge = DefaultCookieMaxAge // 1 hour.
	}

	c := &http.Cookie{
		Name:     b.opts.MaxTriesCookie,
		Path:     "/",
		Value:    strconv.Itoa(tries),
		HttpOnly: true,
		Expires:  time.Now().Add(maxAge),
		MaxAge:   int(maxAge.Seconds()),
	}

	http.SetCookie(w, c)
}

func (b *BasicAuth[U]) resetCurrentTries(w http.ResponseWriter) {
	c := &http.Cookie{
		Name:     b.opts.MaxTriesCookie,
		Path:     "/",
		HttpOnly: true,
		Expires:  cookieExpireDelete,
		MaxAge:   -1,
	}

	http.SetCookie(w, c)
}

func isHTTPS(r *http.Request) bool {
	return (strings.EqualFold(r.URL.Scheme, "https") || r.TLS != nil) && r.ProtoMajor == 2
}

func (b *BasicAuth[U]) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if b.opts.ErrorLogger != nil {
		b.opts.ErrorLogger.Println(err)
	}

	// should not be nil as it's defaulted on New.
	b.opts.ErrorHandler(w, r, err)
}

// serveHTTP is the main method of this middleware,
// checks and verifies the authorization header for basic authentication,
// the next handler will only be executed when the client is allowed to continue.
func (b *BasicAuth[U]) serveHTTP(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if b.opts.HTTPSOnly && !isHTTPS(r) {
		b.handleError(w, r, ErrHTTPVersion{})
		return
	}

	header := r.Header.Get(b.authorizationHeader)
	fullUser, username, password, ok := decodeHeader(header)
	if !ok { // Header is malformed or missing (e.g. browser cancel button on user prompt).
		b.handleError(w, r, ErrCredentialsMissing{
			Header:                  header,
			AuthenticateHeader:      b.authenticateHeader,
			AuthenticateHeaderValue: b.authenticateHeaderValue,
			Code:                    b.askCode,
		})
		return
	}

	var (
		maxTries = b.opts.MaxTries
		tries    int
	)

	if maxTries > 0 {
		tries = b.getCurrentTries(r)
	}

	user, ok := b.opts.Allow(r, username, password)
	if !ok { // This username:password combination was not allowed.
		if maxTries > 0 {
			tries++
			b.setCurrentTries(w, tries)
			if tries >= maxTries { // e.g. if MaxTries == 1 then it should be allowed only once, so we must send forbidden now.
				b.handleError(w, r, ErrCredentialsForbidden{
					Username: username,
					Password: password,
					Tries:    tries,
					Age:      b.opts.MaxAge,
				})
				return
			}
		}

		b.handleError(w, r, ErrCredentialsInvalid{
			Username:                username,
			Password:                password,
			CurrentTries:            tries,
			AuthenticateHeader:      b.authenticateHeader,
			AuthenticateHeaderValue: b.authenticateHeaderValue,
			Code:                    b.askCode,
		})
		return
	}

	if tries > 0 {
		// had failures but it's ok, reset the tries on success.
		b.resetCurrentTries(w)
	}

	now := time.Now()

	b.mu.RLock()
	expiresAt, ok := b.credentials[fullUser]
	b.mu.RUnlock()
	if ok {
		// A zero expiresAt means the entry never expires.
		if !expiresAt.IsZero() && expiresAt.Before(now) { // Has been expired.
			b.mu.Lock() // Delete the entry.
			delete(b.credentials, fullUser)
			b.mu.Unlock()

			// Re-ask for new credentials.
			b.handleError(w, r, ErrCredentialsExpired{
				Username:                username,
				Password:                password,
				AuthenticateHeader:      b.authenticateHeader,
				AuthenticateHeaderValue: b.authenticateHeaderValue,
				Code:                    b.askCode,
			})
			return
		}
	} else {
		// Saved credential not found, first login.
		if b.opts.MaxAge > 0 { // Expiration is enabled, set the value.
			expiresAt = now.Add(b.opts.MaxAge)
		}
		b.mu.Lock()
		b.credentials[fullUser] = expiresAt
		b.mu.Unlock()
	}

	// Store user instance and logout function.
	// Note that the end-developer always has access
	// to the Request.BasicAuth, however, we support any user type,
	// so we must store it on this request instance so it can be retrieved later on.
	r = r.WithContext(newContext(r.Context(), user, b.logout))
	next.ServeHTTP(w, r)
}

// logout clears the current user's credentials.
func (b *BasicAuth[U]) logout(r *http.Request) *http.Request {
	var (
		fullUser string
		ok       bool
	)

	if info := getAuthInfo(r); info != nil { // Get the saved ones, if any.
		if u, isUser := info.user.(User); isUser {
			username, password := u.GetUsername(), u.GetPassword()
			fullUser = username + colonLiteral + password
			ok = username != "" && password != ""
		}

		if b.opts.OnLogoutClearContext {
			// Let's make it clear that we modify the request here by returning it.
			r = r.WithContext(clearContext(r.Context()))
		}
	}

	if !ok {
		// If the custom user does not implement the User interface,
		// then extract from the request header (most common scenario):
		header := r.Header.Get(b.authorizationHeader)
		fullUser, _, _, ok = decodeHeader(header)
	}

	if ok { // If it's authorized then try to lock and delete.
		if b.opts.Proxy {
			r.Header.Del(proxyAuthorizationHeaderKey)
		}
		// delete the request header so future Request().BasicAuth are empty.
		r.Header.Del(authorizationHeaderKey)

		b.mu.Lock()
		delete(b.credentials, fullUser)
		b.mu.Unlock()
	}

	return r
}

// runGC runs a function in a separate go routine
// every x duration to clear in-memory expired credential entries.
func (b *BasicAuth[U]) runGC(ctx context.Context, every time.Duration) {
	if ctx == nil {
		ctx = context.Background()
	}

	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.gc()
		}
	}
}

// gc removes all entries expired based on the max age or all entries (if max age is missing),
// note that this does not mean that the server will send 401/407 to the next request,
// when the request header credentials are still valid (Allow passed).
func (b *BasicAuth[U]) gc() int {
	now := time.Now()

	b.mu.Lock()
	defer b.mu.Unlock()

	before := len(b.credentials)
	maps.DeleteFunc(b.credentials, func(_ string, expiresAt time.Time) bool {
		// Entries without an expiration (MaxAge == 0) are removed as well,
		// as documented on the Options.GC field.
		return expiresAt.IsZero() || expiresAt.Before(now)
	})

	return before - len(b.credentials)
}
