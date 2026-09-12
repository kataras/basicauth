package basicauth

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type IUserRepository interface {
	GetByUsernameAndPassword(dest any, username, password string) error
}

// UserRepository is a usage example of a custom, typed AuthFunc
// backed by a user repository (e.g. a database).
func UserRepository[U any](repo IUserRepository, newUserPtr func() *U) AuthFunc[*U] {
	return func(r *http.Request, username, password string) (*U, bool) {
		dest := newUserPtr()
		err := repo.GetByUsernameAndPassword(dest, username, password)
		if err == nil {
			return dest, true
		}

		return nil, false
	}
}

type testUser struct {
	username string
	password string
	email    string // custom field.
}

// GetUsername & GetPassword complete the User interface.
func (u *testUser) GetUsername() string {
	return u.username
}

func (u *testUser) GetPassword() string {
	return u.password
}

type testRepo struct {
	entries []testUser
}

// Implements IUserRepository interface.
func (r *testRepo) GetByUsernameAndPassword(dest any, username, password string) error {
	for _, e := range r.entries {
		if e.username == username && e.password == password {
			*dest.(*testUser) = e
			return nil
		}
	}

	return errors.New("invalid credentials")
}

func TestAllowUserRepository(t *testing.T) {
	repo := &testRepo{
		entries: []testUser{
			{username: "kataras", password: "kataras_pass", email: "kataras2006@hotmail.com"},
		},
	}

	allow := UserRepository(repo, func() *testUser {
		return new(testUser)
	})

	var tests = []struct {
		username string
		password string
		ok       bool
		user     *testUser
	}{
		{
			username: "kataras",
			password: "kataras_pass",
			ok:       true,
			user:     &testUser{username: "kataras", password: "kataras_pass", email: "kataras2006@hotmail.com"},
		},
		{
			username: "makis",
			password: "makis_password",
			ok:       false,
		},
	}

	for i, tt := range tests {
		u, ok := allow(nil, tt.username, tt.password)

		if tt.ok != ok {
			t.Fatalf("[%d] expected: %v but got: %v (username=%s,password=%s)", i, tt.ok, ok, tt.username, tt.password)
		}

		if !ok {
			continue
		}

		if !reflect.DeepEqual(tt.user, u) {
			t.Fatalf("[%d] expected user:\n%#+v\nbut got:\n%#+v", i, tt.user, u)
		}
	}
}

func TestAllowUsers(t *testing.T) {
	users := []*testUser{
		{username: "kataras", password: "kataras_pass", email: "kataras2006@hotmail.com"},
	}

	allow := AllowUsers(users)

	var tests = []struct {
		username string
		password string
		ok       bool
		user     *testUser
	}{
		{
			username: "kataras",
			password: "kataras_pass",
			ok:       true,
			user:     &testUser{username: "kataras", password: "kataras_pass", email: "kataras2006@hotmail.com"},
		},
		{
			username: "makis",
			password: "makis_password",
			ok:       false,
		},
	}

	for i, tt := range tests {
		u, ok := allow(nil, tt.username, tt.password)

		if tt.ok != ok {
			t.Fatalf("[%d] expected: %v but got: %v (username=%s,password=%s)", i, tt.ok, ok, tt.username, tt.password)
		}

		if !ok {
			continue
		}

		if !reflect.DeepEqual(tt.user, u) {
			t.Fatalf("[%d] expected user:\n%#+v\nbut got:\n%#+v", i, tt.user, u)
		}
	}
}

// A user list through the User interface list type itself.
func TestAllowUsersInterfaceSlice(t *testing.T) {
	users := []User{
		&testUser{username: "kataras", password: "kataras_pass"},
		SimpleUser{Username: "makis", Password: "makis_pass"},
	}

	allow := AllowUsers(users)

	u, ok := allow(nil, "makis", "makis_pass")
	if !ok {
		t.Fatal("expected makis to be allowed")
	}
	if u.GetUsername() != "makis" {
		t.Fatalf("expected the matching list element but got %#+v", u)
	}
	if _, ok = allow(nil, "kataras", "makis_pass"); ok {
		t.Fatal("expected a wrong password to be rejected")
	}
}

func TestAllowUsersCredentialsOption(t *testing.T) {
	type member struct {
		Email string
		Hash  string
	}

	members := []member{
		{Email: "kataras@example.com", Hash: mustGeneratePassword(t, "kataras_pass")},
	}

	allow := AllowUsers(members, Credentials(func(m member) (string, string) {
		return m.Email, m.Hash
	}), BCRYPT)

	m, ok := allow(nil, "kataras@example.com", "kataras_pass")
	if !ok {
		t.Fatal("expected the member to be allowed")
	}
	if m != members[0] {
		t.Fatalf("expected the matching member but got %#+v", m)
	}
	if _, ok = allow(nil, "kataras@example.com", "wrong"); ok {
		t.Fatal("expected a wrong password to be rejected")
	}
}

func TestAllowUsersMap(t *testing.T) {
	users := map[string]string{"kataras": mustGeneratePassword(t, "kataras_pass")}
	allow := AllowUsersMap(users, BCRYPT)

	// The map is copied on creation.
	users["late"] = "late_pass"

	u, ok := allow(nil, "kataras", "kataras_pass")
	if !ok {
		t.Fatal("expected kataras to be allowed")
	}
	if u != (SimpleUser{Username: "kataras", Password: "kataras_pass"}) {
		t.Fatalf("unexpected user: %#+v", u)
	}
	if _, ok = allow(nil, "kataras", "wrong"); ok {
		t.Fatal("expected a wrong password to be rejected")
	}
	if _, ok = allow(nil, "late", "late_pass"); ok {
		t.Fatal("expected changes to the source map to be ignored")
	}
}

// Test YAML user loading with bcrypt-encrypted passwords.
func TestAllowUsersFile(t *testing.T) {
	var tests = []struct {
		username      string
		password      string // hashed, auto-filled later on.
		inputPassword string
		ok            bool
		user          Map
	}{
		{
			username:      "kataras",
			inputPassword: "kataras_pass",
			ok:            true,
			user:          Map{"age": 27, "role": "admin"}, // username and password are auto-filled in our tests below.
		},
		{
			username:      "makis",
			inputPassword: "makis_password",
			ok:            true,
			user:          Map{},
		},
		{
			username: "invalid",
			password: "invalid_pass",
			ok:       false,
		},
		{
			username: "notvalid",
			password: "",
			ok:       false,
		},
	}

	// Write the tests to the users YAML file.
	var usersToWrite []Map
	for _, tt := range tests {
		if tt.ok {
			// store the hashed password.
			tt.password = mustGeneratePassword(t, tt.inputPassword)

			// store and write the username and hashed password.
			tt.user["username"] = tt.username
			tt.user["password"] = tt.password

			usersToWrite = append(usersToWrite, tt.user)
		}
	}

	fileContents, err := yaml.Marshal(usersToWrite)
	if err != nil {
		t.Fatal(err)
	}

	filename := filepath.Join(t.TempDir(), "users.yml")
	if err = os.WriteFile(filename, fileContents, 0o600); err != nil {
		t.Fatal(err)
	}

	// Build the authentication func.
	allow := AllowUsersFile[Map](filename, BCRYPT)
	for i, tt := range tests {
		u, ok := allow(nil, tt.username, tt.inputPassword)

		if tt.ok != ok {
			t.Fatalf("[%d] expected: %v but got: %v (username=%s,password=%s,user=%#+v)", i, tt.ok, ok, tt.username, tt.inputPassword, u)
		}

		if !ok {
			continue
		}

		if expected, got := len(tt.user), len(u); expected != got {
			t.Fatalf("[%d] expected user map length to be equal, expected: %d but got: %d\n%#+v\n%#+v", i, expected, got, tt.user, u)
		}

		for k, v := range tt.user {
			if u[k] != v {
				t.Fatalf("[%d] expected user map %q to be %q but got: %q", i, k, v, u[k])
			}
		}
	}

	// The same file decoded into a typed user.
	type member struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Age      int    `yaml:"age"`
		Role     string `yaml:"role"`
	}

	typed := AllowUsersFile[member](filename, BCRYPT)
	m, ok := typed(nil, "kataras", "kataras_pass")
	if !ok {
		t.Fatal("expected kataras to be allowed through the typed loader")
	}
	if m.Age != 27 || m.Role != "admin" {
		t.Fatalf("unexpected typed user: %#+v", m)
	}
}

func mustGeneratePassword(t *testing.T, userPassword string) string {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte(userPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	return string(hashed)
}
