module myapp

go 1.27

replace github.com/kataras/basicauth => ../../

require (
	github.com/go-sql-driver/mysql v1.10.1
	github.com/kataras/basicauth v0.0.7
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
