package basicauth

import (
	"context"
	"crypto/sha256"
	"log"
	"maps"
	"net"
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
	// It authenticates the request to the proxy server, which then forwards it.
	Proxy bool
	// If set to true then any request that is not served over TLS
	// is immediately dropped with a 505 status code (StatusHTTPVersionNotSupported) response.
	// A request counts as TLS when the connection state is present (r.TLS)
	// or when the URL scheme is https. The HTTP version does not matter,
	// HTTPS over HTTP/1.1 is accepted.
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
	// The expiration is counted from the first successful login and it is not
	// refreshed by later requests: after MaxAge the client is challenged again
	// (ErrCredentialsExpired) and the next successful login starts a new period.
	// An expired entry is removed when its user visits a page again,
	// in order to remove old entries automatically please take a look at the `GC` option too.
	//
	// Usage:
	//  MaxAge: 30 * time.Minute
	MaxAge time.Duration
	// If greater than zero then the server will send 403 forbidden status code after
	// MaxTries amount of sign in failures.
	// The counter is kept on the server side per client address and username
	// (see ClientAddr), and it is mirrored to a client cookie (see MaxTriesCookie)
	// which is not authoritative: a client that does not send the cookie back is still counted.
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
	// ClientAddr returns the address the MaxTries counter is keyed by, together with the username.
	// It defaults to the host part of the request's RemoteAddr.
	// Behind a reverse proxy every request carries the proxy's address,
	// so one client's failures would lock the username out for everyone;
	// set it to read the real client address from the header your proxy sets, e.g.
	//
	//	ClientAddr: func(r *http.Request) string { return r.Header.Get("X-Forwarded-For") }
	//
	// Only used when MaxTries > 0.
	ClientAddr func(r *http.Request) string
	// ErrorHandler handles the given request credentials failure.
	// E.g  when the client tried to access a protected resource
	// with empty or invalid or expired credentials or
	// when Allow returned false and MaxTries consumed.
	//
	// Defaults to the DefaultErrorHandler, do not modify if you don't need to.
	ErrorHandler ErrorHandler
	// ErrorLogger if not nil then it logs any credentials failure errors
	// that are going to be sent to the client. Set it on debug development state.
	// The error messages name the user but never contain the password.
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
	// key = credentialKey(username:password), value = expiration time.
	// The zero time means the entry never expires (MaxAge == 0).
	//
	// The key is a SHA-256 digest of the pair, never the pair itself,
	// so the process does not hold a long-lived cleartext copy of anyone's password.
	credentials map[string]time.Time
	// protects the credentials concurrent access.
	mu sync.RWMutex

	// tries stores the server-side sign in failure counters when MaxTries > 0,
	// key = credentialKey(client address + separator + username).
	tries map[string]*triesEntry
	// protects the tries concurrent access.
	triesMu sync.Mutex
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

	if opts.MaxTries > 0 {
		if opts.MaxTriesCookie == "" {
			opts.MaxTriesCookie = DefaultMaxTriesCookie
		}
		if opts.ClientAddr == nil {
			opts.ClientAddr = remoteHost
		}
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
		tries:                   make(map[string]*triesEntry),
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

// AuthorizedAt returns the time the request's credentials were first accepted.
// It reports false when Options.MaxAge is zero, as the middleware keeps no
// per-login time without an expiration, and when the request did not pass through this middleware.
// See the package-level AuthorizedAt function for handlers without the instance.
func (b *BasicAuth[U]) AuthorizedAt(r *http.Request) (time.Time, bool) {
	return AuthorizedAt(r)
}

// Logout deletes the authenticated user entry from the backend.
// The client should login again on the next request.
// It returns the request to use from now on, which differs from the given one
// only when Options.OnLogoutClearContext is enabled.
func (b *BasicAuth[U]) Logout(r *http.Request) *http.Request {
	return b.logout(r)
}

// maxTriesEntries caps the server-side failure counters. Entries are pruned
// when the cap is reached, expired first, so a flood of distinct usernames
// cannot grow the map without bound.
const maxTriesEntries = 8192

// triesKeySeparator separates the client address from the username
// in the tries key. It cannot appear in either.
const triesKeySeparator = "\x00"

type triesEntry struct {
	count     int
	expiresAt time.Time
}

// remoteHost is the default Options.ClientAddr:
// the host part of the request's RemoteAddr, the whole value when there is no port.
func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}

func (b *BasicAuth[U]) triesKey(r *http.Request, username string) string {
	return credentialKey(b.opts.ClientAddr(r) + triesKeySeparator + username)
}

// getCurrentTries returns the failures recorded for this client and username.
// The server-side counter wins over the cookie: the cookie used to be the only
// record, so a client that simply did not send it back was never counted.
func (b *BasicAuth[U]) getCurrentTries(r *http.Request, username string) (tries int) {
	if cookie, err := r.Cookie(b.opts.MaxTriesCookie); err == nil {
		if v := cookie.Value; v != "" {
			tries, _ = strconv.Atoi(v)
		}
	}

	key := b.triesKey(r, username)
	b.triesMu.Lock()
	if e, ok := b.tries[key]; ok && e.expiresAt.After(time.Now()) && e.count > tries {
		tries = e.count
	}
	b.triesMu.Unlock()

	return tries
}

func (b *BasicAuth[U]) setCurrentTries(w http.ResponseWriter, r *http.Request, username string, tries int) {
	maxAge := b.opts.MaxAge
	if maxAge == 0 {
		maxAge = DefaultCookieMaxAge // 1 hour.
	}

	expiresAt := time.Now().Add(maxAge)

	key := b.triesKey(r, username)
	b.triesMu.Lock()
	b.pruneTriesLocked()
	b.tries[key] = &triesEntry{count: tries, expiresAt: expiresAt}
	b.triesMu.Unlock()

	c := &http.Cookie{
		Name:     b.opts.MaxTriesCookie,
		Path:     "/",
		Value:    strconv.Itoa(tries),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(maxAge.Seconds()),
	}

	http.SetCookie(w, c)
}

func (b *BasicAuth[U]) resetCurrentTries(w http.ResponseWriter, r *http.Request, username string) {
	key := b.triesKey(r, username)
	b.triesMu.Lock()
	delete(b.tries, key)
	b.triesMu.Unlock()

	if w == nil { // Logout has no response writer at hand.
		return
	}

	c := &http.Cookie{
		Name:     b.opts.MaxTriesCookie,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  cookieExpireDelete,
		MaxAge:   -1,
	}

	http.SetCookie(w, c)
}

// pruneTriesLocked keeps the tries map under maxTriesEntries.
// It must be called with triesMu held.
func (b *BasicAuth[U]) pruneTriesLocked() {
	if len(b.tries) < maxTriesEntries {
		return
	}

	now := time.Now()
	maps.DeleteFunc(b.tries, func(_ string, e *triesEntry) bool {
		return !e.expiresAt.After(now)
	})

	if len(b.tries) < maxTriesEntries {
		return
	}

	// Still full of live entries: forget them all rather than grow without bound.
	// Losing counters is the safe failure, a client just gets its MaxTries again.
	clear(b.tries)
}

// isHTTPS reports whether the request was served over TLS.
// The HTTP version is not part of the check: HTTPS over HTTP/1.1 is TLS all the same.
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.URL.Scheme, "https")
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
		tries = b.getCurrentTries(r, username)
	}

	user, ok := b.opts.Allow(r, username, password)
	if !ok { // This username:password combination was not allowed.
		if maxTries > 0 {
			tries++
			b.setCurrentTries(w, r, username, tries)
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
		b.resetCurrentTries(w, r, username)
	}

	now := time.Now()
	credKey := credentialKey(fullUser)

	b.mu.RLock()
	expiresAt, ok := b.credentials[credKey]
	b.mu.RUnlock()

	var authorizedAt time.Time
	if ok {
		// A zero expiresAt means the entry never expires.
		if !expiresAt.IsZero() {
			if expiresAt.Before(now) { // Has been expired.
				b.mu.Lock() // Delete the entry.
				delete(b.credentials, credKey)
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

			// Still valid, the login time is implied by the stored expiration.
			authorizedAt = expiresAt.Add(-b.opts.MaxAge)
		}
	} else {
		// Saved credential not found, first login.
		if b.opts.MaxAge > 0 { // Expiration is enabled, set the value.
			authorizedAt = now
			expiresAt = now.Add(b.opts.MaxAge)
		}

		b.mu.Lock()
		// Re-check under the write lock: two concurrent first logins for the same
		// user both miss the read above, and the second would otherwise overwrite
		// the first one's expiration with a later one.
		if existing, found := b.credentials[credKey]; found {
			expiresAt = existing
			if !expiresAt.IsZero() {
				// Report the authorization time the stored entry implies
				// rather than this goroutine's own start time.
				authorizedAt = expiresAt.Add(-b.opts.MaxAge)
			}
		} else {
			b.credentials[credKey] = expiresAt
		}
		b.mu.Unlock()
	}

	// Store user instance and logout function.
	// Note that the end-developer always has access
	// to the Request.BasicAuth, however, we support any user type,
	// so we must store it on this request instance so it can be retrieved later on.
	r = r.WithContext(newContext(r.Context(), user, authorizedAt, b.logout))
	next.ServeHTTP(w, r)
}

// credentialKey derives the map key for a "username:password" pair.
//
// The credentials map is keyed by this digest rather than by the pair itself, so
// the process never holds a long-lived cleartext copy of anyone's password.
// SHA-256 is right here: the key only has to be stable and collision-resistant,
// it is not a password-storage hash and is never compared against user input.
func credentialKey(fullUser string) string {
	sum := sha256.Sum256([]byte(fullUser))
	return string(sum[:])
}

// logout clears the current user's credentials.
func (b *BasicAuth[U]) logout(r *http.Request) *http.Request {
	var (
		fullUser, username string
		ok                 bool
	)

	if info := getAuthInfo(r); info != nil { // Get the saved ones, if any.
		if u, isUser := info.user.(User); isUser {
			var password string
			username, password = u.GetUsername(), u.GetPassword()
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
		fullUser, username, _, ok = decodeHeader(header)
	}

	if ok { // If it's authorized then try to lock and delete.
		if b.opts.Proxy {
			r.Header.Del(proxyAuthorizationHeaderKey)
		}
		// delete the request header so future Request().BasicAuth are empty.
		r.Header.Del(authorizationHeaderKey)

		b.mu.Lock()
		delete(b.credentials, credentialKey(fullUser))
		b.mu.Unlock()

		if b.opts.MaxTries > 0 {
			b.resetCurrentTries(nil, r, username)
		}
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
