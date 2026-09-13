package basicauth

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Every error string may be logged by ErrorLogger and rendered into a response
// by a custom ErrorHandler, so none of them may contain the attempted password.
// A failed login is very often a valid user's typo of their real password.
func TestErrorsDoNotLeakPassword(t *testing.T) {
	const secret = "hunter2"
	header, _ := encodeHeader("makis", secret)

	errs := []error{
		ErrCredentialsInvalid{Username: "makis", Password: secret, CurrentTries: 1},
		ErrCredentialsForbidden{Username: "makis", Password: secret, Tries: 3},
		ErrCredentialsExpired{Username: "makis", Password: secret},
	}

	for _, err := range errs {
		msg := err.Error()
		if strings.Contains(msg, secret) {
			t.Errorf("%T.Error() leaks the password: %q", err, msg)
		}
		if !strings.Contains(msg, "makis") {
			t.Errorf("%T.Error() should still name the user, got %q", err, msg)
		}
	}

	// The raw header is base64 of username:password, so it must not be printed either.
	missing := ErrCredentialsMissing{Header: header}
	if msg := missing.Error(); strings.Contains(msg, header) || strings.Contains(msg, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Errorf("ErrCredentialsMissing.Error() leaks the header: %q", msg)
	}
	if msg := (ErrCredentialsMissing{}).Error(); msg != "empty credentials" {
		t.Errorf("unexpected empty credentials message: %q", msg)
	}
}

// The MaxTries lockout used to live only in a client cookie, so a brute-forcer
// simply did not send it. The counter is server-side; the cookie is still
// written for compatibility but is no longer authoritative.
func TestMaxTriesIsServerSide(t *testing.T) {
	auth := New(Options[SimpleUser]{
		Allow:    AllowUsersMap(map[string]string{"makis": "correct"}),
		MaxTries: 3,
	})
	handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// A client that never returns the cookie still gets locked out.
	for range 2 {
		testHandler(t, handler, http.MethodGet, "/", withBasicAuth("makis", "wrong")).statusCode(http.StatusUnauthorized)
	}

	// The third failure crosses MaxTries: forbidden, not another 401 challenge.
	testHandler(t, handler, http.MethodGet, "/", withBasicAuth("makis", "wrong")).statusCode(http.StatusForbidden)

	// Further guesses stay forbidden, so the attacker never gets to try the
	// remaining candidates. A correct password still clears the counter: the
	// feature throttles guessing, it does not lock the account.
	testHandler(t, handler, http.MethodGet, "/", withBasicAuth("makis", "also-wrong")).statusCode(http.StatusForbidden)
	testHandler(t, handler, http.MethodGet, "/", withBasicAuth("makis", "another-guess")).statusCode(http.StatusForbidden)
}

// A correct login must not be affected by another user's failures.
func TestMaxTriesPerUser(t *testing.T) {
	auth := New(Options[SimpleUser]{
		Allow:    AllowUsersMap(map[string]string{"makis": "correct", "other": "pass"}),
		MaxTries: 2,
	})
	handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	testHandler(t, handler, http.MethodGet, "/", withBasicAuth("makis", "wrong")).statusCode(http.StatusUnauthorized)
	testHandler(t, handler, http.MethodGet, "/", withBasicAuth("other", "pass")).statusCode(http.StatusOK)
}

func withRemoteAddr(addr string) requestOption {
	return func(r *http.Request) error {
		r.RemoteAddr = addr
		return nil
	}
}

// The server-side counter is keyed by client address and username, so one
// client's failures do not lock the same username out for everyone else.
func TestMaxTriesPerClientAddr(t *testing.T) {
	auth := New(Options[SimpleUser]{
		Allow:    AllowUsersMap(map[string]string{"makis": "correct"}),
		MaxTries: 2,
	})
	handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	testHandler(t, handler, http.MethodGet, "/", withRemoteAddr("10.0.0.1:1111"), withBasicAuth("makis", "wrong")).statusCode(http.StatusUnauthorized)
	testHandler(t, handler, http.MethodGet, "/", withRemoteAddr("10.0.0.1:2222"), withBasicAuth("makis", "wrong")).statusCode(http.StatusForbidden)

	// Same username, other client (the port must not matter, the host does).
	testHandler(t, handler, http.MethodGet, "/", withRemoteAddr("10.0.0.2:1111"), withBasicAuth("makis", "wrong")).statusCode(http.StatusUnauthorized)
}

// Behind a reverse proxy every request shares the proxy's address, so the
// ClientAddr option lets the application name the real client.
func TestMaxTriesClientAddrOption(t *testing.T) {
	auth := New(Options[SimpleUser]{
		Allow:    AllowUsersMap(map[string]string{"makis": "correct"}),
		MaxTries: 2,
		ClientAddr: func(r *http.Request) string {
			return r.Header.Get("X-Forwarded-For")
		},
	})
	handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	withForwardedFor := func(ip string) requestOption {
		return func(r *http.Request) error {
			r.Header.Set("X-Forwarded-For", ip)
			return nil
		}
	}

	testHandler(t, handler, http.MethodGet, "/", withForwardedFor("203.0.113.1"), withBasicAuth("makis", "wrong")).statusCode(http.StatusUnauthorized)
	testHandler(t, handler, http.MethodGet, "/", withForwardedFor("203.0.113.1"), withBasicAuth("makis", "wrong")).statusCode(http.StatusForbidden)
	testHandler(t, handler, http.MethodGet, "/", withForwardedFor("203.0.113.2"), withBasicAuth("makis", "wrong")).statusCode(http.StatusUnauthorized)
}

// Logout also forgets the failure counter of the client, so a user who signs
// out after a few typos starts clean on the next sign in.
func TestLogoutResetsTries(t *testing.T) {
	auth := New(Options[SimpleUser]{
		Allow:    AllowUsersMap(map[string]string{"makis": "correct"}),
		MaxTries: 3,
	})

	var loggedOut bool
	handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loggedOut {
			return
		}
		loggedOut = true

		// A failure recorded between sign in and sign out.
		auth.setCurrentTries(w, r, "makis", 2)
		auth.Logout(r)
	})

	testHandler(t, handler, http.MethodGet, "/", withBasicAuth("makis", "correct")).statusCode(http.StatusOK)

	auth.triesMu.Lock()
	remaining := len(auth.tries)
	auth.triesMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected logout to drop the tries entry but %d remain", remaining)
	}
}

// The tries cookie is HttpOnly, SameSite=Lax and Secure when the request came over TLS.
func TestMaxTriesCookieFlags(t *testing.T) {
	auth := New(Options[SimpleUser]{
		Allow:    AllowUsersMap(map[string]string{"makis": "correct"}),
		MaxTries: 5,
	})
	handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	plain := testHandler(t, handler, http.MethodGet, "/", withBasicAuth("makis", "wrong"))
	cookie := findCookie(t, plain.resp.Cookies(), DefaultMaxTriesCookie)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Secure {
		t.Fatalf("plain request: unexpected cookie flags: HttpOnly=%v SameSite=%v Secure=%v", cookie.HttpOnly, cookie.SameSite, cookie.Secure)
	}

	withTLS := func(r *http.Request) error {
		r.TLS = &tls.ConnectionState{}
		return nil
	}
	secure := testHandler(t, handler, http.MethodGet, "/", withTLS, withBasicAuth("makis", "wrong"))
	cookie = findCookie(t, secure.resp.Cookies(), DefaultMaxTriesCookie)
	if !cookie.Secure {
		t.Fatal("tls request: expected the tries cookie to be Secure")
	}
}

// An unknown username must cost the same as a known one, otherwise the endpoint
// is a username oracle. Timing is not asserted here (it is inherently flaky);
// what is asserted is that both paths reach the password comparison.
func TestUnknownUserComparesPassword(t *testing.T) {
	compares := 0
	countingCompare := func(opts *UserAuthOptions[SimpleUser]) {
		opts.ComparePassword = func(stored, userPassword string) bool {
			compares++
			return stored == userPassword
		}
	}

	allows := map[string]AuthFunc[SimpleUser]{
		"AllowUsersMap": AllowUsersMap(map[string]string{"makis": "correct"}, countingCompare),
		"AllowUsers":    AllowUsers([]SimpleUser{{"makis", "correct"}}, countingCompare),
	}

	for name, allow := range allows {
		t.Run(name, func(t *testing.T) {
			compares = 0
			if _, ok := allow(nil, "makis", "wrong"); ok {
				t.Fatal("expected the known user with a wrong password to fail")
			}
			knownCompares := compares

			compares = 0
			if _, ok := allow(nil, "does-not-exist", "wrong"); ok {
				t.Fatal("expected the unknown user to fail")
			}

			if compares != knownCompares {
				t.Fatalf("unknown username ran %d password comparisons, a known one ran %d: "+
					"the difference is measurable and enumerates valid usernames", compares, knownCompares)
			}
		})
	}
}

// The BCRYPT option must compare against a real bcrypt hash on an unknown
// username too, otherwise the missing user is answered in microseconds.
func TestBCRYPTDecoyIsABcryptHash(t *testing.T) {
	options := toUserAuthOptions([]UserAuthOption[SimpleUser]{BCRYPT[SimpleUser]})
	if !strings.HasPrefix(options.decoyPassword, "$2") {
		t.Fatalf("expected a bcrypt hash as the decoy but got %q", options.decoyPassword)
	}
}

// The default comparator is constant-time. Correctness must be identical to a
// plain equality check, including for length-mismatched input.
func TestDefaultComparePassword(t *testing.T) {
	compare := toUserAuthOptions[SimpleUser](nil).ComparePassword

	var tests = []struct {
		stored string
		input  string
		ok     bool
	}{
		{"kataras_pass", "kataras_pass", true},
		{"kataras_pass", "Kataras_pass", false},  // case-sensitive
		{"kataras_pass", "kataras_pas", false},   // shorter input
		{"kataras_pass", "kataras_passs", false}, // longer input
		{"", "", true},
		{"kataras_pass", "", false},
	}

	for i, tt := range tests {
		if got := compare(tt.stored, tt.input); got != tt.ok {
			t.Fatalf("[%d] ComparePassword(%q, %q) = %v, want %v", i, tt.stored, tt.input, got, tt.ok)
		}
	}
}

// The credentials map must never hold the cleartext username:password pair,
// so a heap dump of a long-running process does not hand over live passwords.
func TestCredentialsAreNotStoredInCleartext(t *testing.T) {
	auth := Default(map[string]string{"makis": "correct"})
	testHandler(t, auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), http.MethodGet, "/", withBasicAuth("makis", "correct")).statusCode(http.StatusOK)

	auth.mu.RLock()
	defer auth.mu.RUnlock()
	if len(auth.credentials) != 1 {
		t.Fatalf("expected one stored credential but got %d", len(auth.credentials))
	}
	for key := range auth.credentials {
		if strings.Contains(key, "makis") || strings.Contains(key, "correct") {
			t.Fatalf("credentials key holds the cleartext pair: %q", key)
		}
	}
}

func TestAuthorizedAt(t *testing.T) {
	t.Run("without MaxAge", func(t *testing.T) {
		auth := Default(map[string]string{"makis": "correct"})
		handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := AuthorizedAt(r); ok {
				t.Error("expected AuthorizedAt to report false without MaxAge")
			}
		})
		testHandler(t, handler, http.MethodGet, "/", withBasicAuth("makis", "correct")).statusCode(http.StatusOK)

		if _, ok := AuthorizedAt(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
			t.Fatal("expected AuthorizedAt to report false on a request that skipped the middleware")
		}
	})

	t.Run("with MaxAge", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			auth := New(Options[SimpleUser]{
				Allow:  AllowUsersMap(map[string]string{"makis": "correct"}),
				MaxAge: 10 * time.Minute,
			})

			var (
				seen   []time.Time
				logout bool
			)
			handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				at, ok := AuthorizedAt(r)
				if !ok {
					t.Fatal("expected AuthorizedAt to report true with MaxAge")
				}
				if methodAt, ok := auth.AuthorizedAt(r); !ok || !methodAt.Equal(at) {
					t.Fatalf("method and package function disagree: %v vs %v", methodAt, at)
				}
				seen = append(seen, at)

				if logout {
					auth.Logout(r)
				}
			})
			login := func() {
				testHandler(t, handler, http.MethodGet, "/", withBasicAuth("makis", "correct")).statusCode(http.StatusOK)
			}

			start := time.Now()
			login()
			time.Sleep(time.Minute)
			login()
			if len(seen) != 2 || !seen[0].Equal(start) || !seen[1].Equal(start) {
				t.Fatalf("expected both requests to report the first login time %v but got %v", start, seen)
			}

			// After a logout the next login is a fresh authorization.
			logout = true
			login()
			logout = false
			time.Sleep(time.Minute)
			login()
			if last := seen[len(seen)-1]; !last.Equal(start.Add(2 * time.Minute)) {
				t.Fatalf("expected a fresh authorization time after logout but got %v (start %v)", last, start)
			}
		})
	})
}
