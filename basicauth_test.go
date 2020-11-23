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

	opts := Options{
		Realm:                DefaultRealm,
		Allow:                AllowUsers(users),
		OnLogoutClearContext: true,
	}
	auth := New(opts)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := GetUser(r).(user) // test get user by sending it as a json response.
		if !ok {
			t.Fatal("unexpected user type")
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		err := json.NewEncoder(w).Encode(u)
		if err != nil {
			t.Fatal(err)
		}

		// test OnLogoutClearContext
		r = Logout(r)
		username, password, ok := r.BasicAuth()
		if ok {
			t.Fatalf("expected request's basic authentication credentials to be removed but got: %s:%s", username, password)
		}

		v := GetUser(r)
		if v != nil {
			t.Fatalf("expected a nil user as its stored credentials removed but got: %#+v", v)
		}
	})

	var tests = []struct {
		username, password string
		ok                 bool
		user               interface{}
	}{
		{"kataras", "kataras_pass", true, users[0]},
		{"george", "george_pass", true, users[1]},
		{"kataras", "invalid_pass", false, nil},
		{"george", "invalid_pass", false, nil},
		{"invalid", "invalid_pass", false, nil},
	}

	for i, tt := range tests {
		te := testHandler(t, auth(handler), http.MethodGet, "/",
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
