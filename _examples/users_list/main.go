package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/kataras/basicauth"
)

// User is just an example structure of a user.
// It MUST contain Username and Password exported fields (json tags count too),
// or complete the basicauth.User interface,
// or be described with the basicauth.Credentials option.
type User struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

var users = []User{
	{"admin", "admin", []string{"admin"}},
	{"kataras", "kataras_pass", []string{"manager", "author"}},
	{"george", "george_pass", []string{"member"}},
	{"john", "john_pass", []string{}},
}

// auth is typed by the User: auth.User(r) returns a User, no type assertion needed.
var auth = basicauth.New(basicauth.Options[User]{
	Realm: basicauth.DefaultRealm,
	// Defaults to 0, no expiration.
	// Prompt for new credentials on a client's request
	// made after 10 minutes the user has logged in:
	MaxAge: 10 * time.Minute,
	// Clear any expired users from the memory every one hour,
	// note that the user's expiration time will be
	// reset on the next valid request (when Allow passed).
	GC: basicauth.GC{
		Every: 2 * time.Hour,
	},
	// The users are a slice of your own user structure,
	// see basicauth.AllowUsersMap and basicauth.AllowUsersFile for the other forms
	// and read the godocs for more.
	Allow: basicauth.AllowUsers(users),
})

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", auth.Wrap(mux)))
}

func index(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.User(r) // user is a User.
	if !ok {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(user)
}
