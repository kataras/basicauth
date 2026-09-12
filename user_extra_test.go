package basicauth

import (
	"os"
	"path/filepath"
	"testing"
)

// Users given as plain structs are matched by field name or by json tag,
// including fields promoted from embedded structs.
func TestAllowUsersStructTags(t *testing.T) {
	type credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	type taggedUser struct {
		Name   string `json:"username"`
		Secret string `json:"password"`
		Email  string `json:"email"`
	}

	type embeddedUser struct {
		credentials
		Email string
	}

	type ptrEmbeddedUser struct {
		*credentials
		Role string
	}

	// allowFuncs erases the user type so the table below can hold every form.
	allowFuncs := map[string]func(username, password string) bool{
		"json tags":                      erase(AllowUsers([]taggedUser{{Name: "kataras", Secret: "kataras_pass", Email: "k@example.com"}})),
		"embedded struct":                erase(AllowUsers([]embeddedUser{{credentials{"kataras", "kataras_pass"}, "k@example.com"}})),
		"embedded pointer":               erase(AllowUsers([]ptrEmbeddedUser{{&credentials{"kataras", "kataras_pass"}, "admin"}})),
		"pointer elements":               erase(AllowUsers([]*taggedUser{{Name: "kataras", Secret: "kataras_pass"}})),
		"nil pointer element is skipped": erase(AllowUsers([]*taggedUser{nil, {Name: "kataras", Secret: "kataras_pass"}})),
		"map elements":                   erase(AllowUsers([]Map{{"username": "kataras", "password": "kataras_pass", "role": "admin"}})),
	}

	for name, allow := range allowFuncs {
		t.Run(name, func(t *testing.T) {
			if !allow("kataras", "kataras_pass") {
				t.Fatal("expected the user to be allowed")
			}
			if allow("kataras", "wrong") {
				t.Fatal("expected a wrong password to be rejected")
			}
			if allow("unknown", "kataras_pass") {
				t.Fatal("expected an unknown username to be rejected")
			}
		})
	}

	t.Run("map elements keep their fields", func(t *testing.T) {
		allow := AllowUsers([]Map{{"username": "kataras", "password": "kataras_pass", "role": "admin"}})
		u, ok := allow(nil, "kataras", "kataras_pass")
		if !ok || u["role"] != "admin" {
			t.Fatalf("expected the map user to be allowed, got %#+v (ok=%v)", u, ok)
		}
	})

	t.Run("unusable elements are skipped", func(t *testing.T) {
		allow := AllowUsers([]int{1, 2})
		if _, ok := allow(nil, "1", "2"); ok {
			t.Fatal("expected no user to match")
		}
	})
}

func erase[U any](allow AuthFunc[U]) func(username, password string) bool {
	return func(username, password string) bool {
		_, ok := allow(nil, username, password)
		return ok
	}
}

func TestAllowUsersFileJSON(t *testing.T) {
	writeTemp := func(t *testing.T, name, contents string) string {
		t.Helper()
		filename := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(filename, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return filename
	}

	t.Run("username password map as Map", func(t *testing.T) {
		name := writeTemp(t, "users.json", `{"kataras": "kataras_pass", "makis": "makis_pass"}`)
		allow := AllowUsersFile[Map](name)

		u, ok := allow(nil, "makis", "makis_pass")
		if !ok {
			t.Fatal("expected makis to be allowed")
		}
		if u["username"] != "makis" || u["password"] != "makis_pass" {
			t.Fatalf("unexpected map user: %#+v", u)
		}
		if _, ok := allow(nil, "makis", "kataras_pass"); ok {
			t.Fatal("expected a wrong password to be rejected")
		}
	})

	t.Run("username password map as SimpleUser", func(t *testing.T) {
		name := writeTemp(t, "users.json", `{"kataras": "kataras_pass"}`)
		allow := AllowUsersFile[SimpleUser](name)

		u, ok := allow(nil, "kataras", "kataras_pass")
		if !ok {
			t.Fatal("expected kataras to be allowed")
		}
		if u != (SimpleUser{Username: "kataras", Password: "kataras_pass"}) {
			t.Fatalf("unexpected user: %#+v", u)
		}
	})

	t.Run("username password map as custom type panics", func(t *testing.T) {
		type member struct{ Username, Password string }
		name := writeTemp(t, "users.json", `{"kataras": "kataras_pass"}`)
		defer func() {
			if recover() == nil {
				t.Fatal("expected a panic: the short form cannot fill a custom type")
			}
		}()
		AllowUsersFile[member](name)
	})

	t.Run("user list", func(t *testing.T) {
		name := writeTemp(t, "users.json", `[{"username": "kataras", "password": "kataras_pass", "role": "admin"}]`)
		allow := AllowUsersFile[Map](name)

		u, ok := allow(nil, "kataras", "kataras_pass")
		if !ok {
			t.Fatal("expected kataras to be allowed")
		}
		if u["role"] != "admin" {
			t.Fatalf("expected role admin but got %v", u["role"])
		}
	})

	t.Run("typed user list", func(t *testing.T) {
		type member struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		name := writeTemp(t, "users.json", `[{"username": "kataras", "password": "kataras_pass", "role": "admin"}]`)
		allow := AllowUsersFile[member](name)

		u, ok := allow(nil, "kataras", "kataras_pass")
		if !ok {
			t.Fatal("expected kataras to be allowed")
		}
		if u.Role != "admin" {
			t.Fatalf("expected role admin but got %q", u.Role)
		}
	})

	t.Run("unsupported extension", func(t *testing.T) {
		name := writeTemp(t, "users.toml", `kataras = "kataras_pass"`)
		defer func() {
			if recover() == nil {
				t.Fatal("expected a panic for an unsupported file extension")
			}
		}()
		AllowUsersFile[Map](name)
	})

	t.Run("missing file", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected a panic for a missing file")
			}
		}()
		AllowUsersFile[Map](filepath.Join(t.TempDir(), "missing.yml"))
	})

	t.Run("malformed file", func(t *testing.T) {
		name := writeTemp(t, "users.json", `"just a string"`)
		defer func() {
			if recover() == nil {
				t.Fatal("expected a panic for a malformed file")
			}
		}()
		AllowUsersFile[Map](name)
	})
}
