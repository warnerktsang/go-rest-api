package auth

import (
	"context"
	"fmt"
	routing "github.com/go-ozzo/ozzo-routing/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/qiangxue/go-rest-api/internal/entity"
	"github.com/qiangxue/go-rest-api/internal/errors"
	"net/http"
	"strings"
)

// realm is the authentication realm reported in the WWW-Authenticate header.
const realm = "API"

// Handler returns a JWT-based authentication middleware.
// It parses the "Authorization: Bearer <token>" header, verifies the token signature (HS256 only)
// and its registered claims (exp, nbf), and stores the user identity in the request context.
// If the header is missing or the token is invalid, a "WWW-Authenticate" header is sent and
// an http.StatusUnauthorized error is returned.
func Handler(verificationKey string) routing.Handler {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	keyFunc := func(*jwt.Token) (interface{}, error) { return []byte(verificationKey), nil }

	return func(c *routing.Context) error {
		header := c.Request.Header.Get("Authorization")
		message := ""
		if strings.HasPrefix(header, "Bearer ") {
			token, err := parser.Parse(header[7:], keyFunc)
			if err == nil && token.Valid {
				err = handleToken(c, token)
			}
			if err == nil {
				return nil
			}
			message = err.Error()
		}

		c.Response.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`"`)
		if message != "" {
			return routing.NewHTTPError(http.StatusUnauthorized, message)
		}
		return routing.NewHTTPError(http.StatusUnauthorized)
	}
}

// handleToken stores the user identity in the request context so that it can be accessed elsewhere.
func handleToken(c *routing.Context, token *jwt.Token) error {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("unexpected claims type %T", token.Claims)
	}
	id, ok := claims["id"].(string)
	if !ok {
		return fmt.Errorf("token is missing the id claim")
	}
	name, ok := claims["name"].(string)
	if !ok {
		return fmt.Errorf("token is missing the name claim")
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
