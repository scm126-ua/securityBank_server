package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"securityBank_server/internal/services"
)

// Comprueba que únicamente un JWT RS256 válido permite acceder a una ruta protegida.
func TestAuthenticationRejectsInvalidTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar la clave de prueba: %v", err)
	}

	validToken := signTestToken(t, privateKey, jwt.MapClaims{
		"user_id": 42,
		"jti":     "valid-token",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	revokedToken := signTestToken(t, privateKey, jwt.MapClaims{
		"user_id": 42,
		"jti":     "revoked-token",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	revokedTokens := services.NewRevokedTokens()
	revokedTokens.Revoke("revoked-token", time.Now().Add(time.Hour))
	expiredToken := signTestToken(t, privateKey, jwt.MapClaims{
		"user_id": 42,
		"exp":     time.Now().Add(-time.Hour).Unix(),
	})
	missingUserToken := signTestToken(t, privateKey, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	hsToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 42,
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	encodedHSToken, err := hsToken.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("no se pudo firmar el token HS256 de prueba: %v", err)
	}

	tests := []struct {
		name           string
		token          string
		expectedStatus int
	}{
		{name: "sin token", expectedStatus: http.StatusUnauthorized},
		{name: "algoritmo HS256", token: encodedHSToken, expectedStatus: http.StatusUnauthorized},
		{name: "firma manipulada", token: tamperTestToken(validToken), expectedStatus: http.StatusUnauthorized},
		{name: "token caducado", token: expiredToken, expectedStatus: http.StatusUnauthorized},
		{name: "usuario ausente", token: missingUserToken, expectedStatus: http.StatusUnauthorized},
		{name: "sesión cerrada", token: revokedToken, expectedStatus: http.StatusUnauthorized},
		{name: "token válido", token: validToken, expectedStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performProtectedRequest(&privateKey.PublicKey, revokedTokens, test.token)
			if response.Code != test.expectedStatus {
				t.Fatalf(
					"estado inesperado: obtenido %d, esperado %d",
					response.Code,
					test.expectedStatus,
				)
			}
			if test.expectedStatus == http.StatusOK &&
				!strings.Contains(response.Body.String(), `"user_id":42`) {
				t.Fatal("el identificador autenticado no llegó a la ruta protegida")
			}
		})
	}
}

// Firma un JWT de prueba con la clave RSA indicada.
func signTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	encodedToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("no se pudo firmar el token de prueba: %v", err)
	}

	return encodedToken
}

// Modifica la firma sin alterar la estructura del JWT.
func tamperTestToken(encodedToken string) string {
	parts := strings.Split(encodedToken, ".")
	if len(parts) != 3 || parts[2] == "" {
		return encodedToken + "x"
	}

	replacement := byte('A')
	if parts[2][0] == replacement {
		replacement = 'B'
	}
	parts[2] = string(replacement) + parts[2][1:]

	return strings.Join(parts, ".")
}

// Ejecuta una petición contra una ruta protegida por el middleware real.
func performProtectedRequest(
	publicKey *rsa.PublicKey,
	revokedTokens *services.RevokedTokens,
	encodedToken string,
) *httptest.ResponseRecorder {
	router := gin.New()
	router.GET("/protected", AuthMiddleware(publicKey, revokedTokens), func(c *gin.Context) {
		userID, _ := c.Get("userID")
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if encodedToken != "" {
		request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: encodedToken})
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	return response
}
