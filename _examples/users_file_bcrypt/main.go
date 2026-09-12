package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/kataras/basicauth"
)

func main() {
	// Load decodes the file into basicauth.Map users (map[string]any),
	// every field of the file is kept.
	auth := basicauth.Load("users.yml", basicauth.BCRYPT)
	/* Same as:
	auth := basicauth.New(basicauth.Options[basicauth.Map]{
		Realm: basicauth.DefaultRealm,
		Allow: basicauth.AllowUsersFile[basicauth.Map]("users.yml", basicauth.BCRYPT),
	})

	Or decode straight into your own type:
	type User struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Age      int    `yaml:"age"`
		Role     string `yaml:"role"`
	}
	auth := basicauth.New(basicauth.Options[User]{
		Realm: basicauth.DefaultRealm,
		Allow: basicauth.AllowUsersFile[User]("users.yml", basicauth.BCRYPT),
	})
	*/

	mux := http.NewServeMux()
	mux.HandleFunc("/", auth.HandlerFunc(index))
	log.Println("Listening on :8080")
	// kataras:kataras_pass
	// makis:makis_pass
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func index(w http.ResponseWriter, r *http.Request) {
	user, _ := basicauth.GetUser[basicauth.Map](r)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(user)
}
