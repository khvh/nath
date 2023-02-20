package nath

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"
)

// CodeResponse == oidc successful login data
type CodeResponse struct {
	AccessToken      string `json:"access_token" url:"accessToken"`
	ExpiresIn        int    `json:"expires_in" url:"expiresIn"`
	RefreshExpiresIn int    `json:"refresh_expires_in" url:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token" url:"refresh_token"`
	TokenType        string `json:"token_type" url:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy" url:"notBeforePolicy"`
	SessionState     string `json:"session_state" url:"sessionState"`
	Scope            string `json:"scope" url:"scope"`
}

func keys(issuer, jwksPath string) (jwk.Set, error) {
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	p := fmt.Sprintf("%s/%s", issuer, jwksPath)

	c := jwk.NewCache(ctx)

	c.Register(p, jwk.WithMinRefreshInterval(30*time.Minute))

	keySet, err := c.Refresh(ctx, p)
	if err != nil {
		return nil, err
	}

	return keySet, err
}

func (s *Server) mountAuthEndpoints() *Server {
	authURL := fmt.Sprintf(
		"%s/%s?client_id=%s&redirect_uri=%s&response_type=code",
		s.oidc.Issuer,
		s.oidc.AuthURI,
		s.oidc.ClientID,
		url.QueryEscape(s.oidc.RedirectURI),
	)

	s.f.Get("/api/auth", func(c *fiber.Ctx) error {
		return c.Redirect(authURL, http.StatusTemporaryRedirect)
	})

	s.f.All("/api/auth/code", func(c *fiber.Ctx) error {
		form := url.Values{}

		form.Add("grant_type", "authorization_code")
		form.Add("client_id", s.oidc.ClientID)
		form.Add("client_secret", s.oidc.Secret)
		form.Add("code", c.Query("code"))
		form.Add("redirect_uri", s.oidc.RedirectURI)

		req, err := http.
			NewRequest(
				http.MethodPost, fmt.Sprintf("%s/%s", s.oidc.Issuer, s.oidc.TokenURI), strings.NewReader(form.Encode()))
		if err != nil {
			log.Err(fmt.Errorf("create http client %w", err)).Send()

			return c.Status(http.StatusBadRequest).JSON(nil)
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Err(fmt.Errorf("send code req %w", err)).Send()

			return c.Status(http.StatusBadRequest).JSON(nil)
		}

		bts, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Err(fmt.Errorf("read body %w", err)).Send()

			return c.Status(http.StatusBadRequest).JSON(nil)
		}

		var data CodeResponse

		err = json.Unmarshal(bts, &data)
		if err != nil {
			log.Err(fmt.Errorf("unmarshal %w", err)).Send()

			return c.Status(http.StatusBadRequest).JSON(nil)
		}

		v, err := query.Values(data)
		if err != nil {
			log.Err(fmt.Errorf("encode %w", err)).Send()

			return c.Status(http.StatusBadRequest).JSON(nil)
		}

		return c.Redirect(fmt.Sprintf("%s?%s", s.oidc.ClientRedirectURI, v.Encode()), http.StatusTemporaryRedirect)
	})

	s.f.All("/api/auth/userinfo", func(c *fiber.Ctx) error {
		claims, err := s.ValidateJWTToken(c.UserContext(), c.Query("accessToken"))
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(nil)
		}

		return c.JSON(claims)
	})

	return s
}

// ValidateJWTRequest validates jwt against jwks etc
func (s *Server) ValidateJWTRequest(ctx context.Context, req *http.Request) (map[string]any, error) {
	token, err := jwt.ParseRequest(req)
	if err != nil {
		return nil, err
	}

	claims, err := token.AsMap(ctx)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// ValidateJWTToken validates jwt against jwks etc
func (s *Server) ValidateJWTToken(ctx context.Context, token string) (map[string]any, error) {
	verified, err := jwt.ParseString(token, jwt.WithKeySet(s.jwks))
	if err != nil {
		return nil, err
	}

	claims, err := verified.AsMap(ctx)
	if err != nil {
		return nil, err
	}

	return claims, nil
}