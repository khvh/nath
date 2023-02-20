package nath

import (
	"errors"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/khvh/nath/spec"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"net/http"
)

// Route ...
type Route struct {
	spec    *spec.Spec
	handler []fiber.Handler
	//handler    echo.HandlerFunc
	//middleware []echo.MiddlewareFunc
}

// Get route constructor
func Get[O any](path string, handler ...fiber.Handler) *Route {
	s := spec.Get(path, zeroGeneric[O]())

	r := &Route{
		s,
		handler,
	}

	return r
}

// Delete route constructor
func Delete[O any](path string, handler ...fiber.Handler) *Route {
	s := spec.Delete(path, zeroGeneric[O]())

	r := &Route{
		s,
		handler,
	}

	return r
}

// Post route constructor
func Post[O any, B any](path string, handler ...fiber.Handler) *Route {
	s := spec.Post(path, zeroGeneric[B](), zeroGeneric[O]())
	handlers := withValidator(zeroGeneric[B](), handler...)

	r := &Route{
		s,
		handlers,
	}

	return r
}

// Put route constructor
func Put[O any, B any](path string, handler ...fiber.Handler) *Route {
	s := spec.Put(path, zeroGeneric[B](), zeroGeneric[O]())
	handlers := withValidator(zeroGeneric[B](), handler...)

	r := &Route{
		s,
		handlers,
	}

	return r
}

// Patch route constructor
func Patch[O any, B any](path string, handler ...fiber.Handler) *Route {
	s := spec.Patch(path, zeroGeneric[B](), zeroGeneric[O]())
	handlers := withValidator(zeroGeneric[B](), handler...)

	r := &Route{
		s,
		handlers,
	}

	return r
}

// Group returns path, rts for nath.Server Group
func Group(path string, rts ...*Route) (string, []*Route) {
	return path, rts
}

// WithAuth mark spec that it needs to be authenticated
func (r *Route) WithAuth() *Route {
	r.spec.WithAuth()

	return r
}

// WithAPIAuth mark spec that it needs to be authenticated with api key
func (r *Route) WithAPIAuth() *Route {
	r.spec.WithAPIAuth()

	return r
}

// WithSpecOpts adds additional spec values to Spec
func (r *Route) WithSpecOpts(s ...spec.Opt) *Route {
	r.spec.With(s...)

	return r
}

// Body binds echo.Context.Body to a provided value, returns nil on error
func Body[T any](c echo.Context) *T {
	var t T

	if err := c.Bind(&t); err != nil {
		log.Err(err).Send()
		return nil
	}

	return &t
}

// BodyP binds echo.Context.Body to a provided value, panics on error
func BodyP[T any](c echo.Context) *T {
	o := Body[T](c)
	if o == nil {
		log.Fatal().Err(errors.New("cant unmarshal json body")).Send()
	}

	return o
}

func zeroGeneric[T any]() T {
	var t T

	return t
}

func collectErrors(err error) []string {
	var errs []string

	for _, err := range err.(validator.ValidationErrors) {
		errs = append(errs, err.Error())
	}

	return errs
}

func withValidator(obj any, handler ...fiber.Handler) []fiber.Handler {
	handlers := []fiber.Handler{
		func(c *fiber.Ctx) error {
			err := validator.New().Struct(obj)
			if err != nil {
				return c.Status(http.StatusBadRequest).JSON(fiber.Map{
					"errors": collectErrors(err),
				})
			}

			return c.Next()
		},
	}

	handlers = append(handlers, handler...)

	return handlers
}