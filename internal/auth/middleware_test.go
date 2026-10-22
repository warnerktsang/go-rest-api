package auth

import (
	"context"
	routing "github.com/go-ozzo/ozzo-routing/v2"
	"github.com/golang-jwt/jwt"
	"github.com/qiangxue/go-rest-api/internal/test"
	"github.com/qiangxue/go-rest-api/pkg/log"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCurrentUser(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, CurrentUser(ctx))
	ctx = WithUser(ctx, "100", "test")
	identity := CurrentUser(ctx)
	if assert.NotNil(t, identity) {
		assert.Equal(t, "100", identity.GetID())
		assert.Equal(t, "test", identity.GetName())
	}
}

func TestHandler(t *testing.T) {
	assert.NotNil(t, Handler("test"))
}

func Test_handleToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx, _ := test.MockRoutingContext(req)
	assert.Nil(t, CurrentUser(ctx.Request.Context()))

	err := handleToken(ctx, &jwt.Token{
		Claims: jwt.MapClaims{
			"id":   "100",
			"name": "test",
		},
	})
	assert.Nil(t, err)
	identity := CurrentUser(ctx.Request.Context())
	if assert.NotNil(t, identity) {
		assert.Equal(t, "100", identity.GetID())
		assert.Equal(t, "test", identity.GetName())
	}
}

func TestMocks(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx, _ := test.MockRoutingContext(req)
	assert.NotNil(t, MockAuthHandler(ctx))
	req.Header = MockAuthHeader()
	ctx, _ = test.MockRoutingContext(req)
	assert.Nil(t, MockAuthHandler(ctx))
	assert.NotNil(t, CurrentUser(ctx.Request.Context()))
}

// --- SEC-2041 regression tests for the token-validation path ---

const testSigningKey = "LxsKJywDL5O5PvgODZhBH12KE6k2yL8E"

// signToken signs claims with the given method. SigningMethodNone uses the
// library's magic constant as the key so an alg=none token can be produced.
func signToken(t *testing.T, key string, method jwt.SigningMethod, claims jwt.MapClaims) string {
	var k interface{} = []byte(key)
	if method == jwt.SigningMethodNone {
		k = jwt.UnsafeAllowNoneSignatureType
	}
	s, err := jwt.NewWithClaims(method, claims).SignedString(k)
	if err != nil {
		t.Fatalf("signing test token: %v", err)
	}
	return s
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"id":   "100",
		"name": "demo",
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
}

// authorize runs the JWT middleware against a request carrying the given Authorization header.
func authorize(t *testing.T, key, authorization string) (*routing.Context, error) {
	req, _ := http.NewRequest("GET", "http://example.com/v1/albums", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	ctx, _ := test.MockRoutingContext(req)
	return ctx, Handler(key)(ctx)
}

func assertUnauthorized(t *testing.T, err error) {
	if !assert.Error(t, err) {
		return
	}
	httpErr, ok := err.(routing.HTTPError)
	if assert.True(t, ok, "expected routing.HTTPError, got %T", err) {
		assert.Equal(t, http.StatusUnauthorized, httpErr.StatusCode())
	}
}

func TestHandler_ValidTokenRoundTrip(t *testing.T) {
	logger, _ := log.NewForTest()
	token, err := NewService(testSigningKey, 1, logger).Login(context.Background(), "demo", "pass")
	assert.Nil(t, err)

	ctx, err := authorize(t, testSigningKey, "Bearer "+token)
	assert.Nil(t, err)
	identity := CurrentUser(ctx.Request.Context())
	if assert.NotNil(t, identity) {
		assert.Equal(t, "100", identity.GetID())
		assert.Equal(t, "demo", identity.GetName())
	}
}

func TestHandler_RejectsInvalidTokens(t *testing.T) {
	valid := signToken(t, testSigningKey, jwt.SigningMethodHS256, validClaims())

	expired := validClaims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()

	// Tampered: header.payload from a token claiming a different identity, signature from the genuine one.
	forged := validClaims()
	forged["id"] = "999"
	forgedParts := strings.Split(signToken(t, testSigningKey, jwt.SigningMethodHS256, forged), ".")
	validParts := strings.Split(valid, ".")
	tampered := forgedParts[0] + "." + forgedParts[1] + "." + validParts[2]

	missingID := validClaims()
	delete(missingID, "id")
	missingName := validClaims()
	delete(missingName, "name")
	numericID := validClaims()
	numericID["id"] = 100

	tests := []struct {
		name          string
		authorization string
	}{
		{"expired", "Bearer " + signToken(t, testSigningKey, jwt.SigningMethodHS256, expired)},
		{"tampered payload", "Bearer " + tampered},
		{"wrong key", "Bearer " + signToken(t, "some-other-key", jwt.SigningMethodHS256, validClaims())},
		{"alg=none", "Bearer " + signToken(t, testSigningKey, jwt.SigningMethodNone, validClaims())},
		{"alg=HS512 (not the configured method)", "Bearer " + signToken(t, testSigningKey, jwt.SigningMethodHS512, validClaims())},
		{"malformed: not a JWT", "Bearer not-a-jwt"},
		{"malformed: three garbage segments", "Bearer a.b.c"},
		{"malformed: empty bearer", "Bearer "},
		{"malformed: non-bearer scheme", "Basic " + valid},
		{"missing header", ""},
		{"signed but missing id claim", "Bearer " + signToken(t, testSigningKey, jwt.SigningMethodHS256, missingID)},
		{"signed but missing name claim", "Bearer " + signToken(t, testSigningKey, jwt.SigningMethodHS256, missingName)},
		{"signed but id claim is not a string", "Bearer " + signToken(t, testSigningKey, jwt.SigningMethodHS256, numericID)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, err := authorize(t, testSigningKey, tc.authorization)
			assertUnauthorized(t, err)
			assert.Nil(t, CurrentUser(ctx.Request.Context()), "no identity must be stored for a rejected token")
		})
	}
}
