package basicauth

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"testing/synctest"
	"time"
)

func TestMaxTries(t *testing.T) {
	const maxTries = 3

	auth := New(Options[SimpleUser]{
		Realm:    DefaultRealm,
		Allow:    AllowUsersMap(map[string]string{"kataras": "kataras_pass"}),
		MaxTries: maxTries,
	})

	handler := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Wrong password: the tries cookie increments on every failure
	// and the last allowed failure returns 403 instead of 401.
	var tries int
	for i := 1; i <= maxTries; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth("kataras", "wrong")
		if tries > 0 {
			req.AddCookie(&http.Cookie{Name: DefaultMaxTriesCookie, Value: strconv.Itoa(tries)})
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		expected := http.StatusUnauthorized
		if i == maxTries {
			expected = http.StatusForbidden
		}
		if w.Code != expected {
			t.Fatalf("[%d] expected status %d but got %d", i, expected, w.Code)
		}

		cookie := findCookie(t, w.Result().Cookies(), DefaultMaxTriesCookie)
		if cookie.Value != strconv.Itoa(i) {
			t.Fatalf("[%d] expected tries cookie value %d but got %q", i, i, cookie.Value)
		}
		if cookie.MaxAge != int(DefaultCookieMaxAge.Seconds()) {
			t.Fatalf("[%d] expected cookie max age %d but got %d", i, int(DefaultCookieMaxAge.Seconds()), cookie.MaxAge)
		}
		if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("[%d] expected an HttpOnly SameSite=Lax cookie but got HttpOnly=%v SameSite=%v", i, cookie.HttpOnly, cookie.SameSite)
		}
		tries = i
	}

	// A successful login after failures resets the cookie.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("kataras", "kataras_pass")
	req.AddCookie(&http.Cookie{Name: DefaultMaxTriesCookie, Value: "1"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 but got %d", w.Code)
	}
	cookie := findCookie(t, w.Result().Cookies(), DefaultMaxTriesCookie)
	if cookie.MaxAge != -1 {
		t.Fatalf("expected the tries cookie to be deleted (MaxAge -1) but got MaxAge %d", cookie.MaxAge)
	}
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q not found", name)
	return nil
}

// errorCapture records the last error handed to the ErrorHandler
// and then delegates to the DefaultErrorHandler.
type errorCapture struct {
	last error
}

func (c *errorCapture) handle(w http.ResponseWriter, r *http.Request, err error) {
	c.last = err
	DefaultErrorHandler(w, r, err)
}

func loginFunc(handler http.Handler, username, password string) func() int {
	return func() int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth(username, password)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
}

func TestMaxAgeExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxAge = 10 * time.Minute

		capture := new(errorCapture)
		auth := New(Options[SimpleUser]{
			Allow:        AllowUsersMap(map[string]string{"kataras": "kataras_pass"}),
			MaxAge:       maxAge,
			ErrorHandler: capture.handle,
		})
		login := loginFunc(auth.Wrap(http.NotFoundHandler()), "kataras", "kataras_pass")

		if code := login(); code != http.StatusNotFound {
			t.Fatalf("first login: expected the next handler (404) but got %d", code)
		}

		time.Sleep(maxAge / 2)
		if code := login(); code != http.StatusNotFound {
			t.Fatalf("login before expiration: expected the next handler (404) but got %d", code)
		}

		time.Sleep(maxAge/2 + time.Second)
		if code := login(); code != http.StatusUnauthorized {
			t.Fatalf("login after expiration: expected 401 but got %d", code)
		}

		expired, ok := errors.AsType[ErrCredentialsExpired](capture.last)
		if !ok {
			t.Fatalf("expected ErrCredentialsExpired but got %T: %v", capture.last, capture.last)
		}
		if expired.Username != "kataras" {
			t.Fatalf("expected expired username to be kataras but got %q", expired.Username)
		}

		// The expired entry was removed, so the same credentials log in again as a first login.
		if code := login(); code != http.StatusNotFound {
			t.Fatalf("re-login after expiration: expected the next handler (404) but got %d", code)
		}
	})
}

func TestGC(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			maxAge = 10 * time.Minute
			every  = time.Hour
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		capture := new(errorCapture)
		auth := New(Options[SimpleUser]{
			Allow:        AllowUsersMap(map[string]string{"kataras": "kataras_pass"}),
			MaxAge:       maxAge,
			ErrorHandler: capture.handle,
			GC:           GC{Context: ctx, Every: every},
		})
		login := loginFunc(auth.Wrap(http.NotFoundHandler()), "kataras", "kataras_pass")

		if code := login(); code != http.StatusNotFound {
			t.Fatalf("first login: expected the next handler (404) but got %d", code)
		}

		auth.mu.RLock()
		stored := len(auth.credentials)
		auth.mu.RUnlock()
		if stored != 1 {
			t.Fatalf("expected one stored credential but got %d", stored)
		}

		// Past the max age and past a GC tick: the expired entry has been collected,
		// so the next request is a fresh first login rather than an expired one (401).
		time.Sleep(every + time.Second)
		synctest.Wait()

		auth.mu.RLock()
		stored = len(auth.credentials)
		auth.mu.RUnlock()
		if stored != 0 {
			t.Fatalf("expected the gc to remove the expired credential but %d remain", stored)
		}

		if code := login(); code != http.StatusNotFound {
			t.Fatalf("login after gc: expected the next handler (404) but got %d (last error: %v)", code, capture.last)
		}
		if capture.last != nil {
			t.Fatalf("expected no error after gc but got: %v", capture.last)
		}
	})
}

func TestProxy(t *testing.T) {
	auth := New(Options[SimpleUser]{
		Realm: DefaultRealm,
		Proxy: true,
		Allow: AllowUsersMap(map[string]string{"kataras": "kataras_pass"}),
	})

	srv := httptest.NewTestServer(t, auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.User(r)
		if !ok {
			t.Error("expected an authenticated user")
			return
		}
		_, _ = io.WriteString(w, u.Username)
	}))
	client := srv.Client()

	// Without credentials the proxy challenge is a 407 with Proxy-Authenticate.
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407 but got %d", resp.StatusCode)
	}
	if got := resp.Header.Get(proxyAuthenticateHeaderKey); got != `Basic realm="Authorization Required"` {
		t.Fatalf("unexpected Proxy-Authenticate header: %q", got)
	}
	if got := resp.Header.Get(authenticateHeaderKey); got != "" {
		t.Fatalf("expected no WWW-Authenticate header but got %q", got)
	}

	// Credentials must be sent through Proxy-Authorization, not Authorization.
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("kataras", "kataras_pass")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("Authorization header should be ignored in proxy mode, expected 407 but got %d", resp.StatusCode)
	}

	req, err = http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := encodeHeader("kataras", "kataras_pass")
	req.Header.Set(proxyAuthorizationHeaderKey, header)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 but got %d", resp.StatusCode)
	}
	if string(body) != "kataras" {
		t.Fatalf("expected body to be the username but got %q", body)
	}
}

func TestHTTPSOnly(t *testing.T) {
	auth := New(Options[SimpleUser]{
		HTTPSOnly: true,
		Allow:     AllowUsersMap(map[string]string{"kataras": "kataras_pass"}),
	})
	handler := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	tests := []struct {
		name     string
		tls      bool
		proto    int
		expected int
	}{
		{"plain http/1.1", false, 1, http.StatusHTTPVersionNotSupported},
		{"tls http/1.1", true, 1, http.StatusOK},
		{"plain http/2", false, 2, http.StatusHTTPVersionNotSupported},
		{"tls http/2", true, 2, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.SetBasicAuth("kataras", "kataras_pass")
			req.ProtoMajor = tt.proto
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tt.expected {
				t.Fatalf("expected status %d but got %d", tt.expected, w.Code)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	type customUser struct {
		Username string
		Password string
		Role     string
	}

	auth := New(Options[customUser]{
		Allow: AllowUsers([]customUser{{"kataras", "kataras_pass", "admin"}}),
	})

	var called bool
	handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		u, ok := auth.User(r)
		if !ok {
			t.Fatal("expected a customUser")
		}
		if u.Role != "admin" {
			t.Fatalf("expected role admin but got %q", u.Role)
		}

		if pkgUser, ok := GetUser[customUser](r); !ok || pkgUser != u {
			t.Fatalf("GetUser[customUser] mismatch: %#+v (ok=%v)", pkgUser, ok)
		}

		if _, ok := GetUser[SimpleUser](r); ok {
			t.Fatal("expected the type mismatch to report false")
		}
	})

	te := testHandler(t, handler, http.MethodGet, "/", withBasicAuth("kataras", "kataras_pass"))
	te.statusCode(http.StatusOK)
	if !called {
		t.Fatal("handler was not called")
	}

	// No user stored at all.
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := GetUser[customUser](plain); ok {
		t.Fatal("expected false when no user is stored in the request")
	}
	if _, ok := auth.User(plain); ok {
		t.Fatal("expected false when no user is stored in the request")
	}
	if got := Logout(plain); got != plain {
		t.Fatal("Logout on a request without a user should return the same request")
	}
}

func TestNewPanicsWithoutAllow(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected New to panic when Allow is nil")
		}
	}()
	New(Options[SimpleUser]{})
}
