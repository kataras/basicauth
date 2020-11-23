package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/kataras/basicauth"
)

func main() {
	auth := basicauth.Default(map[string]string{
		"admin": "admin", // username:password
		"john":  "p@ss",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", index)

	log.Println("Listening on :8080")
	http.ListenAndServe(":8080", auth(mux))
}

func index(w http.ResponseWriter, r *http.Request) {
	// Get the current user, as stored in the Allow field.
	user := basicauth.GetUser(r)
	// Do what ever with that user, we will send it as JSON
	// back to the client, for the sake of the example:
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(user)
}
