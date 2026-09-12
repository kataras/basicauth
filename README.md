# Basic Authentication

[![build status](https://img.shields.io/github/actions/workflow/status/kataras/basicauth/ci.yml?style=for-the-badge)](https://github.com/kataras/basicauth/actions) [![report card](https://img.shields.io/badge/report%20card-a%2B-ff3333.svg?style=for-the-badge)](https://goreportcard.com/report/github.com/kataras/basicauth) [![godocs](https://img.shields.io/badge/go-%20docs-488AC7.svg?style=for-the-badge)](https://pkg.go.dev/github.com/kataras/basicauth)

A Go HTTP middleware for basic authentication with a typed user. It works with the [net/http](https://pkg.go.dev/net/http) package and with third-party routers that accept `func(http.Handler) http.Handler`.

In the context of an HTTP transaction, basic access authentication is a method for an HTTP user agent (e.g. a web browser) to provide a user name and password when making a request [RFC 7617](https://tools.ietf.org/html/rfc7617).

> Looking for JWT? Navigate through [kataras/jwt](https://github.com/kataras/jwt) instead.

## Installation

The only requirement is the [Go Programming Language](https://go.dev/dl/), version 1.27 or newer.

```sh
$ go get github.com/kataras/basicauth
```

Please star this open source project to attract more developers so that together we can improve it even more!

### Examples

- [Basic](_examples/basic/main.go)
- [Load from a slice of Users](_examples/users_list/main.go)
- [Load from a file & encrypted passwords](_examples/users_file_bcrypt)
- [Fetch & validate a User from a Database (MySQL)](_examples/database)

## Getting Started

Import the package:

```go
import "github.com/kataras/basicauth"
```

Initialize the middleware with a simple map of username:password:

```go
auth := basicauth.Default(map[string]string{
	"admin":       "admin",
	"my_username": "my_password",
})
```

Wrap any `http.Handler` with the `auth` middleware, e.g. `*http.ServeMux`:

```go
mux := http.NewServeMux()
// [...routes]

http.ListenAndServe(":8080", auth.Wrap(mux))
```

Or register the middleware to a single `http.HandlerFunc` route:

```go
mux.HandleFunc("/", auth.HandlerFunc(routeHandlerFunc))
```

Access the authenticated User entry. `Default` stores a `basicauth.SimpleUser`, so that is what `User` returns, no type assertion needed:

```go
routeHandlerFunc := func(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.User(r)
	// user.Username
	// user.Password
}
```

Handlers that live in another package and do not hold the `auth` value can use the package-level accessor with the user type as a type argument:

```go
user, ok := basicauth.GetUser[basicauth.SimpleUser](r)
```

### Your own user type

The middleware is generic over the user type. Whatever `Allow` returns is what the handlers get back:

```go
type User struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

auth := basicauth.New(basicauth.Options[User]{
	Realm:  basicauth.DefaultRealm,
	MaxAge: 10 * time.Minute,
	Allow:  basicauth.AllowUsers(users), // users is a []User
})

func index(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.User(r) // user is a User.
}
```

`AllowUsers` reads the username and password from the `basicauth.User` interface when the type implements it, otherwise from the `Username` and `Password` fields (json tags count too). For anything else pass the `basicauth.Credentials` option and tell it where to look. All of this happens once, at startup; a request costs one map lookup and one password comparison.

For a database or any other backend, write the `Allow` function yourself. It returns your type directly:

```go
auth := basicauth.New(basicauth.Options[*User]{
	Realm: basicauth.DefaultRealm,
	Allow: func(r *http.Request, username, password string) (*User, bool) {
		user, err := db.find(r.Context(), username, password)
		return user, err == nil
	},
})
```

Users from a YAML or JSON file, with bcrypt-hashed passwords:

```go
auth := basicauth.Load("users.yml", basicauth.BCRYPT)             // users are basicauth.Map (map[string]any)
auth := basicauth.New(basicauth.Options[User]{
	Allow: basicauth.AllowUsersFile[User]("users.yml", basicauth.BCRYPT), // or decode straight into your type
})
```

> The `*http.Request.BasicAuth()` works too, but it only gives you the raw username and password, not your [custom user](_examples/users_list/main.go).

For a more detailed technical documentation you can head over to our [godocs](https://pkg.go.dev/github.com/kataras/basicauth).

## License

This software is licensed under the [MIT License](LICENSE).
