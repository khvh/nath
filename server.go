package nath

import (
	"embed"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	recover2 "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/imdario/mergo"
	"github.com/khvh/nath/queue"
	"github.com/khvh/nath/spec"
	"github.com/khvh/nath/telemetry"
	"github.com/labstack/echo-contrib/prometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog/log"
	"github.com/swaggest/openapi-go/openapi3"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/otel"
)

// ServerOptions ...
type ServerOptions struct {
	ID            string `json:"id,omitempty" yaml:"id,omitempty"`
	Description   string `json:"description,omitempty" yaml:"description,omitempty"`
	Version       string `json:"version,omitempty" yaml:"version,omitempty"`
	Host          string `json:"host,omitempty" yaml:"host,omitempty"`
	Port          int    `json:"port,omitempty" yaml:"port,omitempty"`
	HideBanner    bool   `json:"hideBanner,omitempty" yaml:"hideBanner,omitempty"`
	RequestLogger bool   `json:"requestLogger,omitempty" yaml:"requestLogger,omitempty"`
}

// OIDCOptions ...
type OIDCOptions struct {
	Issuer            string `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	AuthURI           string `json:"authUri,omitempty" yaml:"authUri,omitempty"`
	KeysURI           string `json:"keysURI,omitempty" yaml:"keysURI,omitempty"`
	TokenURI          string `json:"tokenURI,omitempty" yaml:"tokenURI,omitempty"`
	ClientID          string `json:"clientId,omitempty" yaml:"clientId,omitempty"`
	Secret            string `json:"secret,omitempty" yaml:"secret,omitempty"`
	RedirectURI       string `json:"redirectURI,omitempty" yaml:"redirectURI,omitempty"`
	ClientRedirectURI string `json:"clientRedirectURI,omitempty" yaml:"clientRedirectURI,omitempty"`
}

// Server ...
type Server struct {
	e      *echo.Echo
	f      *fiber.App
	routes []*Route
	ref    *openapi3.Reflector
	opts   *ServerOptions
	oidc   *OIDCOptions
	jwks   jwk.Set
}

// Configuration ...
type Configuration func(s *Server) error

// New constructs Server
func New(cfgs ...Configuration) *Server {
	s := &Server{
		routes: []*Route{},
	}

	for _, cfg := range cfgs {
		if err := cfg(s); err != nil {
			log.Fatal().Err(fmt.Errorf("apply server configuration %w", err)).Send()

			return nil
		}
	}

	if s.e == nil {
		s.e = createEcho(s.opts.HideBanner)
	}

	if s.f == nil {
		s.f = createFiber(s.opts.HideBanner)
	}

	s.ref = spec.CreateReflector(&spec.ReflectorOptions{
		Servers:     addresses(),
		Port:        s.opts.Port,
		Title:       s.opts.ID + "-api",
		Description: s.opts.Description,
		Version:     s.opts.Version,
		//OpenAPIAuthorizationURL: fmt.Sprintf("%s/%s", s.oidc.Issuer, s.oidc.AuthURI),
		APIKeyAuth: false,
	})

	return s
}

// Route ...
func (s *Server) Route(routes ...*Route) *Server {

	for _, rt := range routes {
		//  if rt.spec.Auth {
		//    rt.middleware = append(rt.middleware, func(next echo.HandlerFunc) echo.HandlerFunc {
		//      return func(c echo.Context) error {
		//        claims, err := s.ValidateJWTToken(c.Request().Context(), strings.ReplaceAll(c.Request().Header.Get("authorization"), "Bearer ", ""))
		//        if err != nil {
		//          log.Err(err).Send()
		//          return c.JSON(http.StatusUnauthorized, nil)
		//        }
		//
		//        c.Set("claims", claims)
		//
		//        return next(c)
		//      }
		//    })
		//  }

		err := rt.spec.Build(s.ref)
		if err != nil {
			log.Err(err).Send()
		}

		//  switch rt.spec.Method {
		//  case spec.MethodGet:
		//    s.e.GET(rt.spec.FullRouterPath(), rt.handler, rt.middleware...)
		//  case spec.MethodDelete:
		//    s.e.DELETE(rt.spec.FullRouterPath(), rt.handler, rt.middleware...)
		//  case spec.MethodPost:
		//    s.e.POST(rt.spec.FullRouterPath(), rt.handler, rt.middleware...)
		//  case spec.MethodPut:
		//    s.e.PUT(rt.spec.FullRouterPath(), rt.handler, rt.middleware...)
		//  case spec.MethodPatch:
		//    s.e.PATCH(rt.spec.FullRouterPath(), rt.handler, rt.middleware...)
		//  }
		//
	}

	//yamlBytes, err := s.ref.Spec.MarshalYAML()
	//if err != nil {
	//	log.Err(err).Send()
	//}

	for _, rt := range routes {
		switch rt.spec.Method {
		case spec.MethodGet:
			s.f.Get(rt.spec.FullRouterPath(), rt.handler...)
		case spec.MethodDelete:
			s.f.Delete(rt.spec.FullRouterPath(), rt.handler...)
		case spec.MethodPost:
			handlers := []fiber.Handler{
				func(c *fiber.Ctx) error {
					log.Info().Msg("validate")

					bts, err := rt.spec.Op.MarshalJSON()
					log.Info().Err(err).Send()

					fmt.Println(string(bts))

					return c.Next()
				},
			}

			handlers = append(handlers, rt.handler...)

			s.f.Post(rt.spec.FullRouterPath(), handlers...)
		case spec.MethodPut:
			s.f.Put(rt.spec.FullRouterPath(), rt.handler...)
		case spec.MethodPatch:
			s.f.Patch(rt.spec.FullRouterPath(), rt.handler...)
		}
	}

	return s
}

// Group groups routes
func (s *Server) Group(path string, routes ...*Route) *Server {
	for _, r := range routes {
		r.WithSpecOpts(spec.WithPathPrefix(path))
	}

	s.Route(routes...)

	return s
}

// Routes registers routes for path
func (s *Server) Routes(path string, routes []*Route) *Server {
	return s.Group(path, routes...)
}

// WithOpts create Server with options
func WithOpts(opts ...ServerOptions) Configuration {
	return func(s *Server) error {
		s.opts = createDefaults(opts...)

		return nil
	}
}

// WithDefaultMiddleware ...
func WithDefaultMiddleware() Configuration {
	return func(s *Server) error {
		if s.e == nil {
			s.e = createEcho(s.opts.HideBanner)
			s.f = createFiber(s.opts.HideBanner)
		}

		s.e.Use(middleware.RequestID())
		s.e.Use(middleware.CORS())
		s.e.Use(middleware.Recover())

		s.f.Use(requestid.New())
		s.f.Use(recover2.New())
		s.f.Use(cors.New())
		s.f.Get("/monitor", monitor.New(monitor.Config{Title: s.opts.ID}))

		return nil
	}
}

// WithRequestLogger ...
func WithRequestLogger() Configuration {
	return func(s *Server) error {
		if s.e == nil {
			s.e = createEcho(s.opts.HideBanner)
			s.f = createFiber(s.opts.HideBanner)
		}

		s.e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
			LogURI:    true,
			LogStatus: true,
			LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
				log.Trace().
					Str("method", c.Request().Method).
					Int("code", v.Status).
					Str("uri", v.URI).
					Str("from", c.Request().RemoteAddr).
					Send()

				return nil
			},
		}))

		return nil
	}
}

// WithTracing ...
func WithTracing(url ...string) Configuration {
	return func(s *Server) error {
		if s.e == nil {
			s.e = createEcho(s.opts.HideBanner)
			s.f = createFiber(s.opts.HideBanner)
		}

		id := strings.ReplaceAll(s.opts.ID, "-", "_")
		u := "http://localhost:14268/api/traces"

		otel.Tracer(id)

		if len(url) > 0 {
			u = url[0]
		}

		telemetry.New(id, u)

		s.e.Use(otelecho.Middleware(id))

		return nil
	}
}

// WithFrontend ...
func WithFrontend(data embed.FS) Configuration {
	return func(s *Server) error {
		if s.e == nil {
			s.e = createEcho(s.opts.HideBanner)
			s.f = createFiber(s.opts.HideBanner)
		}

		return nil
	}
}

// WithQueue ...
func WithQueue(url, pw string, opts queue.Queues, fn func(q *queue.Queue)) Configuration {
	return func(s *Server) error {
		if s.e == nil {
			s.e = createEcho(s.opts.HideBanner)
			s.f = createFiber(s.opts.HideBanner)
		}

		q, mon := queue.
			CreateServer(url, 11, opts).
			MountMonitor("127.0.0.1:6379", "")

		s.e.Any("/monitoring/tasks/*", echo.WrapHandler(mon))

		fn(q)

		q.Run()

		log.Trace().Msgf("Asynq running on http://0.0.0.0:%d/monitoring/tasks", s.opts.Port)

		return nil
	}
}

// WithMetrics ...
func WithMetrics() Configuration {
	return func(s *Server) error {
		if s.e == nil {
			s.e = createEcho(s.opts.HideBanner)
			s.f = createFiber(s.opts.HideBanner)
		}

		prometheus.NewPrometheus(strings.ReplaceAll(s.opts.ID, "-", "_"), nil).Use(s.e)

		return nil
	}
}

// WithOIDC enables OpenID Connect auth
func WithOIDC(opts OIDCOptions) Configuration {
	return func(s *Server) error {
		if s.e == nil {
			s.e = createEcho(s.opts.HideBanner)
		}

		s.oidc = &opts

		keySet, err := keys(opts.Issuer, opts.KeysURI)
		if err != nil {
			log.Err(err).Send()

			return nil
		}

		s.jwks = keySet

		s.mountAuthEndpoints()

		return nil
	}
}

// WithMiddleware add middleware to Echo
func WithMiddleware(middleware ...echo.MiddlewareFunc) Configuration {
	return func(s *Server) error {
		if s.e == nil {
			s.e = createEcho(s.opts.HideBanner)
		}

		s.e.Use(middleware...)

		return nil
	}
}

func (s *Server) build() *Server {
	yamlBytes, err := s.ref.Spec.MarshalYAML()
	if err != nil {
		log.Err(err).Send()

		return s
	}

	s.f.Get("/spec/spec.yaml", func(c *fiber.Ctx) error {
		c.Set("content-type", "application/openapi+yaml")

		return c.Send(yamlBytes)
	})

	s.f.Get("/spec/spec.yml", func(c *fiber.Ctx) error {
		c.Set("content-type", "application/openapi+yaml")

		return c.Send(yamlBytes)
	})

	jsonBytes, err := s.ref.Spec.MarshalJSON()
	if err != nil {
		log.Err(err).Send()

		return s
	}

	s.f.Get("/spec/spec.json", func(c *fiber.Ctx) error {
		c.Set("content-type", "application/openapi+json")

		return c.Send(jsonBytes)
	})

	return s
}

func getFileSystem(embededFiles embed.FS) http.FileSystem {
	sub, err := fs.Sub(embededFiles, "docs")
	if err != nil {
		panic(err)
	}

	return http.FS(sub)
}

//go:embed docs
var content embed.FS

// Run starts the server
func (s *Server) Run() {
	s.build()

	//fsContent := getFileSystem(content)
	//assetHandler := http.FileServer(fsContent)

	//s.e.Any("/docs", echo.WrapHandler(http.StripPrefix("/docs", assetHandler)))
	//s.e.Any("/docs/*", echo.WrapHandler(http.StripPrefix("/docs", assetHandler)))
	//
	//s.e.Any("/oauth-receiver.html*", func(c echo.Context) error {
	//  return c.Redirect(http.StatusTemporaryRedirect, "/docs"+c.Request().RequestURI)
	//})

	for _, host := range addresses() {
		log.
			Info().
			Str("id", s.opts.ID).
			Str("URL", fmt.Sprintf("http://%s:%d", host, s.opts.Port)).
			Str("OpenAPI", fmt.Sprintf("http://%s:%d/docs", host, s.opts.Port)).
			Send()
	}

	log.Info().Str("server", s.opts.ID).Send()

	//log.Err(s.e.Start(fmt.Sprintf("%s:%d", s.opts.Host, s.opts.Port))).Send()
	log.Err(s.f.Listen(fmt.Sprintf("%s:%d", s.opts.Host, s.opts.Port))).Send()
}

func createFiber(hideBanner bool) *fiber.App {
	return fiber.New(fiber.Config{DisableStartupMessage: hideBanner})
}

func createEcho(hideBanner bool) *echo.Echo {
	e := echo.New()

	e.HideBanner = hideBanner
	e.HidePort = hideBanner

	return e
}

func createDefaults(opts ...ServerOptions) *ServerOptions {
	id, err := gonanoid.New()
	if err != nil {
		log.Err(err).Send()
	}

	defaults := ServerOptions{
		ID:            id,
		Port:          1234,
		Host:          "0.0.0.0",
		HideBanner:    true,
		RequestLogger: false,
		Version:       "1.0",
	}

	for _, opt := range opts {
		if err := mergo.Merge(&defaults, opt, mergo.WithSliceDeepCopy); err != nil {
			log.Fatal().Err(fmt.Errorf("merge server options: %w", err)).Send()
		}
	}

	return &defaults
}

// addresses returns addresses the server can bind to
func addresses() []string {
	host, _ := os.Hostname()
	addresses, _ := net.LookupIP(host)

	hosts := []string{
		"127.0.0.1",
		"0.0.0.0",
	}

	for _, addr := range addresses {
		if ipv4 := addr.To4(); ipv4 != nil {
			hosts = append(hosts, ipv4.String())
		}
	}

	return hosts
}