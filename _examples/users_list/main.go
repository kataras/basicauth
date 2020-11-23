package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/kataras/basicauth"
)

// User is just an example structure of a user,
// it MUST contain a Username and Password exported fields
// or complete the basicauth.User interface.
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

func main() {
	opts := basicauth.Options{
		Realm: basicauth.DefaultRealm,
		// Defaults to 0, no expiration.
		// Prompt for new credentials on a client's request
		// made after 10 minutes the user has logged in:
		MaxAge: 20 * time.Second,
		// Clear any expired users from the memory every one hour,
		// note that the user's expiration time will be
		// reseted on the next valid request (when Allow passed).
		GC: basicauth.GC{
			Every: 1 * time.Minute,
		},
		// The users can be a slice of custom users structure
		// or a map[string]string (username:password)
		// or []map[string]interface{} with username and passwords required fields,
		// read the godocs for more.
		Allow: basicauth.AllowUsers(users),
	}

	auth := basicauth.New(opts)
	// OR: basicauth.Default(users)

	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	log.Println("Listening on :8080")
	http.ListenAndServe(":8080", auth(mux))
}

func index(w http.ResponseWriter, r *http.Request) {
	user := basicauth.GetUser(r)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(user)
}
