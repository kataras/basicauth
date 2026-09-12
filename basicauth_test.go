package basicauth

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestNew(t *testing.T) {
	type (
		role string

		user struct {
			Username string
			Password string
			Roles    []role
		}
	)

	users := []user{
		{"kataras", "kataras_pass", []role{"admin"}},
		{"george", "george_pass", []role{}},
	}

	auth := New(Options[user]{
		Realm:                DefaultRealm,
		Allow:                AllowUsers(users),
		OnLogoutClearContext: true,
	})

	handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.User(r) // test get user by sending it as a json response.
		if !ok {
			t.Fatal("expected an authenticated user")
		}

		// The package-level accessor sees the same value.
		if pkgUser, ok := GetUser[user](r); !ok || pkgUser.Username != u.Username {
			t.Fatalf("GetUser mismatch: %#+v (ok=%v) vs %#+v", pkgUser, ok, u)
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		err := json.NewEncoder(w).Encode(u)
		if err != nil {
			t.Fatal(err)
		}

		// test OnLogoutClearContext
		r = auth.Logout(r)
		username, password, ok := r.BasicAuth()
		if ok {
			t.Fatalf("expected request's basic authentication credentials to be removed but got: %s:%s", username, password)
		}

		if v, ok := auth.User(r); ok {
			t.Fatalf("expected no user as its stored credentials were removed but got: %#+v", v)
		}
	})

	var tests = []struct {
		username, password string
		ok                 bool
		user               any
	}{
		{"kataras", "kataras_pass", true, users[0]},
		{"george", "george_pass", true, users[1]},
		{"kataras", "invalid_pass", false, nil},
		{"george", "invalid_pass", false, nil},
		{"invalid", "invalid_pass", false, nil},
	}

	for i, tt := range tests {
		te := testHandler(t, handler, http.MethodGet, "/",
			withRequestID(i), withBasicAuth(tt.username, tt.password),
		)

		if tt.ok {
			te.statusCode(http.StatusOK)
			te.jsonEq(tt.user)
		} else {
			te.statusCode(http.StatusUnauthorized)
		}
	}
}

func TestDefault(t *testing.T) {
	auth := Default(map[string]string{"admin": "admin"})

	handler := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.User(r)
		if !ok {
			t.Fatal("expected a SimpleUser")
		}
		if u.Username != "admin" || u.Password != "admin" {
			t.Fatalf("unexpected user: %#+v", u)
		}
	}))

	testHandler(t, handler, http.MethodGet, "/", withBasicAuth("admin", "admin")).statusCode(http.StatusOK)
	testHandler(t, handler, http.MethodGet, "/", withBasicAuth("admin", "wrong")).statusCode(http.StatusUnauthorized)
	testHandler(t, handler, http.MethodGet, "/").statusCode(http.StatusUnauthorized)
}

func TestMiddlewareAdapters(t *testing.T) {
	auth := Default(map[string]string{"admin": "admin"})
	index := func(w http.ResponseWriter, r *http.Request) {}

	handlers := map[string]http.Handler{
		"Func":        Func(auth.Middleware())(index),
		"HandlerFunc": HandlerFunc(auth.Middleware(), index),
		"method":      auth.HandlerFunc(index),
	}

	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			testHandler(t, handler, http.MethodGet, "/", withBasicAuth("admin", "admin")).statusCode(http.StatusOK)
			testHandler(t, handler, http.MethodGet, "/").statusCode(http.StatusUnauthorized)
		})
	}
}
