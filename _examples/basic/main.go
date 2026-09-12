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
	mux.HandleFunc("/", auth.HandlerFunc(index))

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func index(w http.ResponseWriter, r *http.Request) {
	// Get the current user. Default stores a basicauth.SimpleUser
	// with the username and password the client sent.
	user, _ := basicauth.GetUser[basicauth.SimpleUser](r)
	// Do what ever with that user, we will send it as JSON
	// back to the client, for the sake of the example:
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(user)
}
