package basicauth

import (
	"context"
	"log"
	"net/http"
	"net/url"
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
	// Map is just a type alias of the map[string]interface{}.
	Map = map[string]interface{}
	// Middleware is just a type alias of func(http.Handler) http.Handler
	Middleware = func(http.Handler) http.Handler
)

// Func converts a Middleware of func(http.Handler) http.Handler
// to a func(HandlerFunc) http.HandlerFunc.
// Maybe useful for some third-party handlers chaining.
//
// Usage:
//
//	mux.HandleFunc("/", basicauth.Func(auth)(index))
func Func(auth Middleware) func(http.HandlerFunc) http.HandlerFunc {
	return func(fn http.HandlerFunc) http.HandlerFunc {
		return auth(fn).ServeHTTP
	}
}

// HandlerFunc accepts a Middleware (http.Handler) http.Handler
// and a handler and returns a HandlerFunc.
//
// Usage:
//
//	mux.HandleFunc("/", basicauth.HandlerFunc(auth, index))
func HandlerFunc(auth Middleware, handlerFunc func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return auth(http.HandlerFunc(handlerFunc)).ServeHTTP
}

// AuthFunc accepts the current request and the username and password user inputs
// and it should optionally return a user value and report whether the login succeed or not.
// Look the Options.Allow field.
//
// Default implementations are:
// AllowUsers and AllowUsersFile functions.
type AuthFunc func(r *http.Request, username, password string) (interface{}, bool)

// ErrorHandler should handle the given request credentials failure.
// See Options.ErrorHandler and DefaultErrorHandler for details.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Options holds the necessary information that the BasicAuth instance needs to perform.
// The only required value is the Allow field.
//
// Usage:
//
//	opts := Options { ... }
//	auth := New(opts)
type Options struct {
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
	// If set to true then any non-https request will immediately
	// dropped with a 505 status code (StatusHTTPVersionNotSupported) response.
	//
	// Defaults to false.
	HTTPSOnly bool
	// Allow is the only one required field for the Options type.
	// Can be customized to validate a username and password combination
	// and return a user object, e.g. fetch from database.
	//
	// There are two available builtin values, the AllowUsers and AllowUsersFile,
	// both of them decode a static list of users and compares with the user input (see BCRYPT function too).
	// Usage:
	//  - Allow: AllowUsers(map[string]interface{}{"username": "...", "password": "...", "other_field": ...}, [BCRYPT])
	//  - Allow: AllowUsersFile("users.yml", [BCRYPT])
	// Look the user.go source file for details.
	Allow AuthFunc
	// MaxAge sets expiration duration for the in-memory credentials map.
	// By default an old map entry will be removed when the user visits a page.
	// In order to remove old entries automatically please take a look at the `GC` option too.
	//
	// Usage:
	//  MaxAge: 30 * time.Minute
	MaxAge time.Duration
	// If greater than zero then the server will send 403 forbidden status code afer
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
	// This means that the GetUser will return nil after a Logout call was made.
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
// Read https://tools.ietf.org/html/rfc2617 and
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication for details.
type BasicAuth struct {
	opts Options
	// built based on proxy field
	askCode             int
	authorizationHeader string
	authenticateHeader  string
	// built based on realm field.
	authenticateHeaderValue string

	// credentials stores the user expiration,
	// key = username:password, value = expiration time (if MaxAge > 0).
	credentials map[string]*time.Time // TODO: think of just a uint64 here (unix seconds).
	// protects the credentials concurrent access.
	mu sync.RWMutex
}

// New returns a new basic authentication middleware.
// The result should be used to wrap an existing handler or the HTTP application's root router.
//
// Example Code:
//
//	opts := basicauth.Options{
//		Realm: basicauth.DefaultRealm,
//	    ErrorHandler: basicauth.DefaultErrorHandler,
//		MaxAge: 2 * time.Hour,
//		GC: basicauth.GC{
//			Every: 3 * time.Hour,
//		},
//		Allow: basicauth.AllowUsers(users),
//	}
//	auth := basicauth.New(opts)
//	mux := http.NewServeMux()
//	[...routes]
//	http.ListenAndServe(":8080", auth(mux))
//
// Access the user in the route handler with:
//
//	basicauth.GetUser(r).(*myCustomType) / (*basicauth.SimpleUser).
//
// Look the BasicAuth type docs for more information.
func New(opts Options) Middleware {
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

	b := &BasicAuth{
		opts:                    opts,
		askCode:                 askCode,
		authorizationHeader:     authorizationHeader,
		authenticateHeader:      authenticateHeader,
		authenticateHeaderValue: authenticateHeaderValue,
		credentials:             make(map[string]*time.Time),
	}

	if opts.GC.Every > 0 {
		go b.runGC(opts.GC.Context, opts.GC.Every)
	}

	return b.serveHTTP
}

// Default returns a new basic authentication middleware
// based on pre-defined user list.
// A user can hold any custom fields but the username and password
// are required as they are compared against the user input
// when access to protected resource is requested.
// A user list can defined with one of the following values:
//
//	map[string]string form of: {username:password, ...}
//	map[string]interface{} form of: {"username": {"password": "...", "other_field": ...}, ...}
//	[]T which T completes the User interface, where T is a struct value
//	[]T which T contains at least Username and Password fields.
//
// Usage:
//
//	auth := Default(map[string]string{
//	  "admin": "admin",
//	  "john": "p@ss",
//	})
func Default(users interface{}, userOpts ...UserAuthOption) Middleware {
	opts := Options{
		Realm: DefaultRealm,
		Allow: AllowUsers(users, userOpts...),
	}
	return New(opts)
}

// Load same as Default but instead of a hard-coded user list it accepts
// a filename to load the users from.
//
// Usage:
//
//	auth := Load("users.yml")
func Load(jsonOrYamlFilename string, userOpts ...UserAuthOption) Middleware {
	opts := Options{
		Realm: DefaultRealm,
		Allow: AllowUsersFile(jsonOrYamlFilename, userOpts...),
	}
	return New(opts)
}

func (b *BasicAuth) getCurrentTries(r *http.Request) (tries int) {
	if cookie, err := r.Cookie(b.opts.MaxTriesCookie); err == nil {
		if v := cookie.Value; v != "" {
			tries, _ = strconv.Atoi(v)
		}
	}

	return
}

func (b *BasicAuth) setCurrentTries(w http.ResponseWriter, tries int) {
	maxAge := b.opts.MaxAge
	if maxAge == 0 {
		maxAge = DefaultCookieMaxAge // 1 hour.
	}

	c := &http.Cookie{
		Name:     b.opts.MaxTriesCookie,
		Path:     "/",
		Value:    url.QueryEscape(strconv.Itoa(tries)),
		HttpOnly: true,
		Expires:  time.Now().Add(maxAge),
		MaxAge:   int(maxAge.Seconds()),
	}

	http.SetCookie(w, c)
}

func (b *BasicAuth) resetCurrentTries(w http.ResponseWriter) {
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

func (b *BasicAuth) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if b.opts.ErrorLogger != nil {
		b.opts.ErrorLogger.Println(err)
	}

	// should not be nil as it's defaulted on New.
	b.opts.ErrorHandler(w, r, err)
}

// serveHTTP is the main method of this middleware,
// checks and verifies the auhorization header for basic authentication,
// next handlers will only be executed when the client is allowed to continue.
func (b *BasicAuth) serveHTTP(next http.Handler) http.Handler {
	handler := func(w http.ResponseWriter, r *http.Request) {
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

		b.mu.RLock()
		expiresAt, ok := b.credentials[fullUser]
		b.mu.RUnlock()
		if ok {
			if expiresAt != nil { // Has expiration.
				if expiresAt.Before(time.Now()) { // Has been expired.
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

			}
		} else {
			// Saved credential not found, first login.
			if b.opts.MaxAge > 0 { // Expiration is enabled, set the value.
				t := time.Now().Add(b.opts.MaxAge)
				expiresAt = &t
			}
			b.mu.Lock()
			b.credentials[fullUser] = expiresAt
			b.mu.Unlock()
		}

		if user == nil {
			// No custom uset was set by the auth func,
			// it is passed though, set a simple user here:
			user = &SimpleUser{
				Username: username,
				Password: password,
			}
		}

		// Store user instance and logout function.
		// Note that the end-developer has always have access
		// to the Request.BasicAuth, however, we support any user struct,
		// so we must store it on this request instance so it can be retrieved later on.
		r = r.WithContext(newContext(r.Context(), user, b.logout))
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(handler)
}

// logout clears the current user's credentials.
func (b *BasicAuth) logout(r *http.Request) *http.Request {
	var (
		fullUser, username, password string
		ok                           bool
	)

	if v := GetUser(r); v != nil { // Get the saved ones, if any.
		if u, isUser := v.(User); isUser {
			username = u.GetUsername()
			password = u.GetPassword()
			fullUser = username + colonLiteral + password
			ok = username != "" && password != ""
		}

		if b.opts.OnLogoutClearContext {
			// *r = *(r.WithContext(clearContext(r.Context())))
			// Let's make it clear that we modify the request here by returning it instead of ^
			r = r.WithContext(clearContext(r.Context()))
		}
	}

	if !ok {
		// If the custom user does
		// not implement the User interface, then extract from the request header (most common scenario):
		header := r.Header.Get(b.authorizationHeader)
		fullUser, username, password, ok = decodeHeader(header)
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
func (b *BasicAuth) runGC(ctx context.Context, every time.Duration) {
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
func (b *BasicAuth) gc() int {
	now := time.Now()
	var markedForDeletion []string

	b.mu.RLock()
	for fullUser, expiresAt := range b.credentials {
		if expiresAt == nil || expiresAt.Before(now) {
			markedForDeletion = append(markedForDeletion, fullUser)
		}
	}
	b.mu.RUnlock()

	n := len(markedForDeletion)
	if n > 0 {
		for _, fullUser := range markedForDeletion {
			b.mu.Lock()
			delete(b.credentials, fullUser)
			b.mu.Unlock()
		}
	}

	return n
}
