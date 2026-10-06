module example.com/app

go 1.21

toolchain go1.21.5

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/old/thing v1.0.0
	example.com/local v0.0.0
	golang.org/x/net v0.17.0 // indirect
	github.com/BurntSushi/toml v1.3.2+incompatible
)

require github.com/stretchr/testify v1.8.4

replace github.com/old/thing => github.com/new/thing v1.2.0

replace example.com/local => ../local
