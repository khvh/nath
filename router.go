package nath

import (
  "errors"
  "github.com/gofiber/fiber/v2"
  "github.com/khvh/nath/spec"
  "github.com/labstack/echo/v4"
  "github.com/rs/zerolog/log"
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

  r := &Route{
    s,
    handler,
  }

  return r
}

// Put route constructor
func Put[O any, B any](path string, handler ...fiber.Handler) *Route {
  s := spec.Put(path, zeroGeneric[B](), zeroGeneric[O]())

  r := &Route{
    s,
    handler,
  }

  return r
}

// Patch route constructor
func Patch[O any, B any](path string, handler ...fiber.Handler) *Route {
  s := spec.Patch(path, zeroGeneric[B](), zeroGeneric[O]())

  r := &Route{
    s,
    handler,
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