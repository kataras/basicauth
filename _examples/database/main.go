package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/kataras/basicauth"
)

// User is just an example structure of a user,
// it MUST contain a Username and Password exported fields
// or complete the basicauth.User interface.
type User struct {
	ID       int64  `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Password string `db:"password" json:"password"`
	Email    string `db:"email" json:"email"`
}

func main() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
		getenv("MYSQL_USER", "user_myapp"),
		getenv("MYSQL_PASSWORD", "dbpassword"),
		getenv("MYSQL_HOST", "localhost"),
		getenv("MYSQL_DATABASE", "myapp"),
	)
	db, err := connect(dsn)
	if err != nil {
		log.Fatal(err)
	}

	// Validate a user from database.
	allowFunc := func(r *http.Request, username, password string) (interface{}, bool) {
		user, err := db.getUserByUsernameAndPassword(context.Background(), &user, username, password)
		return user, err == nil
	}

	opts := basicauth.Options{
		Realm:        basicauth.DefaultRealm,
		ErrorHandler: basicauth.DefaultErrorHandler,
		Allow:        allowFunc,
	}

	auth := basicauth.New(opts)

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

func getenv(key string, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	return v
}

type database struct {
	*sql.DB
}

func connect(dsn string) (*database, error) {
	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	err = conn.Ping()
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &database{conn}, nil
}

func (db *database) getUserByUsernameAndPassword(ctx context.Context, username, password string) (User, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE %s = ? AND %s = ? LIMIT 1", "users", "username", "password")
	rows, err := db.QueryContext(ctx, query, username, password)
	if err != nil {
		return Users{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return User{}, sql.ErrNoRows
	}

	var user User
	err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.Email)
	return user, err
}
