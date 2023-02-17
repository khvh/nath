# Nath

Nath is a set of conveniences for quickly setting up a server with OpenAPI support, tracing and telemety.

Nath heavily uses other libraries, eg. Echo, OpenTelemetry, etc. See credits below.

## Features

- Define OpenAPI specs with code
- OpenTelemetry support
- Prometheus metrics
- Integrated job queue with Asynq
- OIDC authentication
- Migrations with Goose

## Usage

### Simple example

```go
nath.
	New(
		nath.WithOpts(nath.ServerOptions{
			Port:       port,
			ID:         os.Getenv("ID"), // used for prometheus and jaeger registration
			HideBanner: true,
		}),
		nath.WithOIDC(nath.OIDCOptions{
			Issuer:            "https://id.example.org",
			AuthURI:           "protocol/openid-connect/auth",
			TokenURI:          "protocol/openid-connect/token",
			ClientID:          "client",
			Secret:            "1234567890",
			KeysURI:           "protocol/openid-connect/certs",
			RedirectURI:       fmt.Sprintf("http://localhost:%d/api/auth/code", port),
			ClientRedirectURI: fmt.Sprintf("http://localhost:%d/api/auth/userinfo", port),
		}),
		nath.WithDefaultMiddleware(),
		nath.WithMetrics(),
	).
	Routes(example.NewResource(example.NewService(example.WithRepository())).Routes()).
	Run()
```

### With migrations etc.

```go
package main

import (
	"embed"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/khvh/nath"
	"github.com/khvh/nath/logger"
	"github.com/khvh/nath/migration"
	"github.com/khvh/thw/db"
	"github.com/khvh/thw/internal/question"
	"github.com/rs/zerolog/log"
)

//go:embed migrations/*.sql
var migrations embed.FS

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Trace().Msg("Error loading .env")
	}

	defaultVal, err := strconv.Atoi(os.Getenv("DEV"))
	if err != nil {
		defaultVal = 1
	}

	logger.Init(defaultVal, defaultVal <= 0)

	flagSet := flag.NewFlagSet("api", flag.ExitOnError)

	err = flagSet.Parse(os.Args[1:])
	if err != nil {
		log.Panic().Err(err).Send()
	}

	args := flagSet.Args()

	if len(args) > 0 && (args[0] == "status" || args[0] == "up" || args[0] == "down") {
		migration.Init(migrations, args, migration.DialectSQLite, os.Getenv("DSN"))
	} else {
		port, err := strconv.Atoi(os.Getenv("PORT"))
		if err != nil {
			port = 3000
		}

		err = db.Init(os.Getenv("DSN"))
		if err != nil {
			log.Fatal().Err(err).Send()
		}

		nath.
			New(
				nath.WithOpts(nath.ServerOptions{
					Port:       port,
					ID:         os.Getenv("ID"), // used for prometheus and jaeger registration
					HideBanner: true,
				}),
				nath.WithOIDC(nath.OIDCOptions{
					Issuer:            "https://id.example.org",
					AuthURI:           "protocol/openid-connect/auth",
					TokenURI:          "protocol/openid-connect/token",
					ClientID:          "client",
					Secret:            "1234567890",
					KeysURI:           "protocol/openid-connect/certs",
					RedirectURI:       fmt.Sprintf("http://localhost:%d/api/auth/code", port),
					ClientRedirectURI: fmt.Sprintf("http://localhost:%d/api/auth/userinfo", port),
				}),
				nath.WithDefaultMiddleware(),
				nath.WithMetrics(),
			).
			Routes(example.NewResource(example.NewService(example.WithRepository())).Routes()).
			Run()
	}
}

```

## Credits

- [Echo](https://github.com/labstack/echo)
- [Swaggest OpenAPI](https://github.com/swaggest/openapi-go)
- [Goose](https://github.com/pressly/goose)
- [OIDC](https://github.com/lestrrat-go/jwx)

## License

[MIT](LICENSE)