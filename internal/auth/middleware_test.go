package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	routing "github.com/go-ozzo/ozzo-routing/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/qiangxue/go-rest-api/internal/entity"
	"github.com/qiangxue/go-rest-api/internal/test"
	"github.com/qiangxue/go-rest-api/pkg/log"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
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

func TestHandler_TokenValidation(t *testing.T) {
	logger, _ := log.NewForTest()
	const signingKey = "test-signing-key"
	s := service{signingKey, 1, logger}
	user := entity.User{ID: "100", Name: "demo"}

	validToken, err := s.generateJWT(user)
	assert.Nil(t, err)
	expiredToken, err := service{signingKey, -1, logger}.generateJWT(user)
	assert.Nil(t, err)
	wrongKeyToken, err := service{"another-key", 1, logger}.generateJWT(user)
	assert.Nil(t, err)
	tamperedToken := tamperPayload(t, validToken, map[string]interface{}{"id": "999"})
	noneAlgToken, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"id": "100", "name": "demo"}).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	assert.Nil(t, err)
	missingClaimToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": "demo",
		"exp":  time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(signingKey))
	assert.Nil(t, err)

	tests := []struct {
		name          string
		authorization string
		wantStatus    int
		wantIdentity  bool
	}{
		{"valid token", "Bearer " + validToken, http.StatusOK, true},
		{"missing header", "", http.StatusUnauthorized, false},
		{"not a bearer token", "Basic abc", http.StatusUnauthorized, false},
		{"malformed token", "Bearer not.a.jwt", http.StatusUnauthorized, false},
		{"expired token", "Bearer " + expiredToken, http.StatusUnauthorized, false},
		{"wrong signing key", "Bearer " + wrongKeyToken, http.StatusUnauthorized, false},
		{"tampered payload", "Bearer " + tamperedToken, http.StatusUnauthorized, false},
		{"none algorithm", "Bearer " + noneAlgToken, http.StatusUnauthorized, false},
		{"missing id claim", "Bearer " + missingClaimToken, http.StatusUnauthorized, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var identity Identity
			router := test.MockRouter(logger)
			router.Use(Handler(signingKey))
			router.Get("/me", func(c *routing.Context) error {
				identity = CurrentUser(c.Request.Context())
				return c.Write(identity)
			})

			req, _ := http.NewRequest("GET", "/me", nil)
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			res := httptest.NewRecorder()
			router.ServeHTTP(res, req)

			assert.Equal(t, tc.wantStatus, res.Code)
			if tc.wantIdentity {
				if assert.NotNil(t, identity) {
					assert.Equal(t, user.ID, identity.GetID())
					assert.Equal(t, user.Name, identity.GetName())
				}
				assert.Empty(t, res.Header().Get("WWW-Authenticate"))
			} else {
				assert.Nil(t, identity)
				assert.Equal(t, `Bearer realm="API"`, res.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func Test_generateJWT_Claims(t *testing.T) {
	logger, _ := log.NewForTest()
	s := service{"test", 2, logger}
	before := time.Now()
	tokenString, err := s.generateJWT(entity.User{ID: "100", Name: "demo"})
	assert.Nil(t, err)

	token, err := jwt.Parse(tokenString, func(*jwt.Token) (interface{}, error) { return []byte("test"), nil })
	if assert.Nil(t, err) && assert.True(t, token.Valid) {
		assert.Equal(t, jwt.SigningMethodHS256.Alg(), token.Method.Alg())
		claims := token.Claims.(jwt.MapClaims)
		assert.Equal(t, "100", claims["id"])
		assert.Equal(t, "demo", claims["name"])
		exp, err := claims.GetExpirationTime()
		if assert.Nil(t, err) && assert.NotNil(t, exp) {
			assert.WithinDuration(t, before.Add(2*time.Hour), exp.Time, 5*time.Second)
		}
	}
}

// tamperPayload re-encodes the JWT payload with the given claim overrides while keeping the original signature.
func tamperPayload(t *testing.T, tokenString string, overrides map[string]interface{}) string {
	parts := strings.Split(tokenString, ".")
	if !assert.Len(t, parts, 3) {
		return tokenString
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	assert.Nil(t, err)
	var claims map[string]interface{}
	assert.Nil(t, json.Unmarshal(payload, &claims))
	for k, v := range overrides {
		claims[k] = v
	}
	payload, err = json.Marshal(claims)
	assert.Nil(t, err)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	return strings.Join(parts, ".")
}
