package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/kataras/basicauth"
)

func main() {
	auth := basicauth.Load("users.yml", basicauth.BCRYPT)
	/* Same as:
	opts := basicauth.Options{
		Realm: basicauth.DefaultRealm,
		Allow: basicauth.AllowUsersFile("users.yml", basicauth.BCRYPT),
	}

	auth := basicauth.New(opts)
	*/

	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	log.Println("Listening on :8080")
	// kataras:kataras_pass
	// makis:makis_pass
	http.ListenAndServe(":8080", auth(mux))
}

func index(w http.ResponseWriter, r *http.Request) {
	user := basicauth.GetUser(r)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(user)
}
