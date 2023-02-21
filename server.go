package nath

import (
	"embed"
	"encoding/json"
	"fmt"
	"github.com/ansrivas/fiberprometheus/v2"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/gofiber/fiber/v2/middleware/proxy"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/google/uuid"
	"github.com/matoous/go-nanoid/v2"
	"io/fs"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gofiber/contrib/otelfiber"
	"github.com/imdario/mergo"
	"github.com/khvh/nath/queue"
	"github.com/khvh/nath/spec"
	"github.com/khvh/nath/telemetry"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog/log"
	"github.com/swaggest/openapi-go/openapi3"
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
	f         *fiber.App
	routes    []*Route
	ref       *openapi3.Reflector
	opts      *ServerOptions
	oidc      *OIDCOptions
	jwks      jwk.Set
	validator *validator.Validate
}

// Configuration ...
type Configuration func(s *Server) error

// New constructs Server
func New(cfgs ...Configuration) *Server {
	s := &Server{
		routes:    []*Route{},
		validator: validator.New(),
		opts: &ServerOptions{
			ID:            uuid.NewString(),
			Description:   "",
			Version:       "1.0.0",
			Host:          "0.0.0.0",
			Port:          rand.Intn(1500),
			HideBanner:    false,
			RequestLogger: false,
		},
	}

	for _, cfg := range cfgs {
		if err := cfg(s); err != nil {
			log.Fatal().Err(fmt.Errorf("apply server configuration %w", err)).Send()

			return nil
		}
	}

	if s.f == nil {
		s.f = createFiber(s.opts.HideBanner)
	}

	refOpts := &spec.ReflectorOptions{
		Servers:     addresses(),
		Port:        s.opts.Port,
		Title:       s.opts.ID + "-api",
		Description: s.opts.Description,
		Version:     s.opts.Version,
		APIKeyAuth:  false,
	}

	if s.oidc != nil {
		refOpts.OpenAPIAuthorizationURL = fmt.Sprintf("%s/%s", s.oidc.Issuer, s.oidc.AuthURI)
	}

	s.ref = spec.CreateReflector(refOpts)

	return s
}

// Route ...
func (s *Server) Route(routes ...*Route) *Server {

	for _, rt := range routes {
		if rt.spec.Auth {
			rt.handler = append([]fiber.Handler{
				func(c *fiber.Ctx) error {
					claims, err := s.
						ValidateJWTToken(c.UserContext(), strings.ReplaceAll(c.Get("authorization"), "Bearer ", ""))
					if err != nil {
						return c.Status(http.StatusUnauthorized).JSON(fiber.Map{})
					}

					c.Locals("claims", claims)

					return c.Next()
				},
			}, rt.handler...)
		}

		err := rt.spec.Build(s.ref)
		if err != nil {
			log.Err(err).Send()
		}

		switch rt.spec.Method {
		case spec.MethodGet:
			s.f.Get(rt.spec.FullRouterPath(), rt.handler...)
		case spec.MethodDelete:
			s.f.Delete(rt.spec.FullRouterPath(), rt.handler...)
		case spec.MethodPost:
			fmt.Println(len(rt.handler))
			s.f.Post(rt.spec.FullRouterPath(), rt.handler...)
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
		if s.f == nil {
			s.f = createFiber(s.opts.HideBanner)
		}

		s.f.Use(requestid.New())
		s.f.Use(recover.New())
		s.f.Use(cors.New())
		s.f.Get("/monitor", monitor.New(monitor.Config{Title: s.opts.ID}))

		return nil
	}
}

// WithTracing ...
func WithTracing(url ...string) Configuration {
	return func(s *Server) error {
		if s.f == nil {
			s.f = createFiber(s.opts.HideBanner)
		}

		id := strings.ReplaceAll(s.opts.ID, "-", "_")
		u := "http://localhost:14268/api/traces"

		otel.Tracer(id)

		if len(url) > 0 {
			u = url[0]
		}

		telemetry.New(id, u)

		s.f.Use(otelfiber.Middleware(otelfiber.WithServerName(id)))

		return nil
	}
}

func (s *Server) startYarnDev(dir string) {
	cmd := exec.Command("yarn", "dev")

	cmd.Dir = dir

	out, err := cmd.Output()

	log.Trace().Err(err).Bytes("out", out).Send()
}

func (s *Server) buildYarn(dir string) {
	cmd := exec.Command("yarn", "build")

	cmd.Dir = dir

	out, err := cmd.Output()

	log.Trace().Err(err).Bytes("out", out).Send()
}

func (s *Server) mountFrontend(ui embed.FS, dir string) *Server {
	s.buildYarn(dir)

	s.f.Use("/*", filesystem.New(filesystem.Config{
		Root:       http.FS(ui),
		PathPrefix: "ui/dist",
		Browse:     false,
	}))

	log.Trace().Msg("Frontend mounted")

	return s
}

// WithFrontend ...
func WithFrontend(data *embed.FS, dir string) Configuration {
	return func(s *Server) error {
		if s.f == nil {
			s.f = createFiber(s.opts.HideBanner)
		}

		if data != nil {
			s.mountFrontend(*data, dir)
		} else {
			go s.startYarnDev(dir)

			log.Trace().Msg("Frontend dev server proxy started")

			fePort := 3000

			file, err := os.ReadFile(dir + "/package.json")
			if err != nil {
				log.Trace().Err(err).Send()
			}

			var packageJson map[string]interface{}

			err = json.Unmarshal(file, &packageJson)
			if err != nil {
				log.Trace().Err(err).Send()
			} else {
				fePort = int(packageJson["devPort"].(float64))
			}

			s.f.Get("/*", func(c *fiber.Ctx) error {
				err := proxy.
					Do(c, strings.
						ReplaceAll(c.Request().URI().String(), strconv.Itoa(s.opts.Port), strconv.Itoa(fePort)),
					)
				if err != nil {
					log.Err(err).Send()
				}

				return c.Send(c.Response().Body())
			})
		}

		return nil
	}
}

// WithQueue ...
func WithQueue(url, pw string, opts queue.Queues, fn func(q *queue.Queue)) Configuration {
	return func(s *Server) error {
		if s.f == nil {
			s.f = createFiber(s.opts.HideBanner)
		}

		q, mon := queue.
			CreateServer(url, 11, opts).
			MountMonitor("127.0.0.1:6379", "")

		//s.e.Any("/monitoring/tasks/*", echo.WrapHandler(mon))

		s.f.All("/monitoring/tasks/*", adaptor.HTTPHandler(mon))

		fn(q)

		q.Run()

		fn(q)

		q.Run()

		log.Trace().Msgf("Asynq running on http://0.0.0.0:%d/monitoring/tasks", s.opts.Port)

		return nil
	}
}

// WithMetrics ...
func WithMetrics() Configuration {
	return func(s *Server) error {
		if s.f == nil {
			s.f = createFiber(s.opts.HideBanner)
		}

		id := strings.ReplaceAll(s.opts.ID, "-", "_")
		prometheus := fiberprometheus.New(id)

		prometheus.RegisterAt(s.f, "/metrics")

		s.f.Use(prometheus.Middleware)

		return nil
	}
}

// WithOIDC enables OpenID Connect auth
func WithOIDC(opts OIDCOptions) Configuration {
	return func(s *Server) error {
		if s.f == nil {
			s.f = createFiber(s.opts.HideBanner)
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
func WithMiddleware(middleware ...fiber.Handler) Configuration {
	return func(s *Server) error {
		if s.f == nil {
			s.f = createFiber(s.opts.HideBanner)
		}

		s.f.Use(middleware)

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

	s.f.Use("/docs", filesystem.New(filesystem.Config{
		Root:       http.FS(content),
		PathPrefix: "/docs",
		Browse:     false,
	}))

	s.f.All("/oauth-receiver.html*", func(c *fiber.Ctx) error {
		return c.Redirect("/docs"+string(c.Request().RequestURI()), http.StatusTemporaryRedirect)
	})

	for _, host := range addresses() {
		log.
			Info().
			Str("id", s.opts.ID).
			Str("URL", fmt.Sprintf("http://%s:%d", host, s.opts.Port)).
			Str("OpenAPI", fmt.Sprintf("http://%s:%d/docs", host, s.opts.Port)).
			Send()
	}

	log.Info().Str("server", s.opts.ID).Send()

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