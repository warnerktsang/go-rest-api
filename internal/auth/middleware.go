package auth

import (
	"context"
	routing "github.com/go-ozzo/ozzo-routing/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/qiangxue/go-rest-api/internal/entity"
	"github.com/qiangxue/go-rest-api/internal/errors"
	"net/http"
	"strings"
)

const (
	bearerPrefix    = "Bearer "
	wwwAuthenticate = `Bearer realm="API"`
)

// Handler returns a JWT-based authentication middleware.
// It accepts only HS256 tokens signed with verificationKey that carry the
// user identity in the "id" and "name" claims. Any other request is answered with 401.
func Handler(verificationKey string) routing.Handler {
	key := []byte(verificationKey)
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	keyFunc := func(*jwt.Token) (interface{}, error) { return key, nil }

	return func(c *routing.Context) error {
		header := c.Request.Header.Get("Authorization")
		c.Response.Header().Set("WWW-Authenticate", wwwAuthenticate)
		if !strings.HasPrefix(header, bearerPrefix) {
			return routing.NewHTTPError(http.StatusUnauthorized)
		}
		token, err := parser.ParseWithClaims(header[len(bearerPrefix):], jwt.MapClaims{}, keyFunc)
		if err == nil && token.Valid {
			err = handleToken(c, token)
		}
		if err != nil {
			return routing.NewHTTPError(http.StatusUnauthorized, err.Error())
		}
		c.Response.Header().Del("WWW-Authenticate")
		return nil
	}
}

// handleToken stores the user identity in the request context so that it can be accessed elsewhere.
func handleToken(c *routing.Context, token *jwt.Token) error {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.Unauthorized("")
	}
	id, idOK := claims["id"].(string)
	name, nameOK := claims["name"].(string)
	if !idOK || !nameOK {
		return errors.Unauthorized("")
	}
	ctx := WithUser(c.Request.Context(), id, name)
	c.Request = c.Request.WithContext(ctx)
	return nil
}

type contextKey int

const (
	userKey contextKey = iota
)

// WithUser returns a context that contains the user identity from the given JWT.
func WithUser(ctx context.Context, id, name string) context.Context {
	return context.WithValue(ctx, userKey, entity.User{ID: id, Name: name})
}

// CurrentUser returns the user identity from the given context.
// Nil is returned if no user identity is found in the context.
func CurrentUser(ctx context.Context) Identity {
	if user, ok := ctx.Value(userKey).(entity.User); ok {
		return user
	}
	return nil
}

// MockAuthHandler creates a mock authentication middleware for testing purpose.
// If the request contains an Authorization header whose value is "TEST", then
// it considers the user is authenticated as "Tester" whose ID is "100".
// It fails the authentication otherwise.
func MockAuthHandler(c *routing.Context) error {
	if c.Request.Header.Get("Authorization") != "TEST" {
		return errors.Unauthorized("")
	}
	ctx := WithUser(c.Request.Context(), "100", "Tester")
	c.Request = c.Request.WithContext(ctx)
	return nil
}

// MockAuthHeader returns an HTTP header that can pass the authentication check by MockAuthHandler.
func MockAuthHeader() http.Header {
	header := http.Header{}
	header.Add("Authorization", "TEST")
	return header
}
