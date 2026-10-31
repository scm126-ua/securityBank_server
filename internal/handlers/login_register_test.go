package handlers

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"securityBank_server/internal/services"
)

// El registro sin 2FA debe llegar al servicio y devolver siempre una respuesta.
// Antes, el handler solo respondía si el usuario activaba TOTP y, en caso
// contrario, terminaba con un 200 sin cuerpo.
func TestRegisterWithoutTOTPReturnsJSONError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	userService := services.NewUserService(nil, nil)
	router := gin.New()
	router.POST("/register", Register(userService, nil))

	salt := base64.StdEncoding.EncodeToString(make([]byte, 16))
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 12))
	ciphertext := base64.StdEncoding.EncodeToString(make([]byte, 32))
	authKey := base64.StdEncoding.EncodeToString(make([]byte, 32))

	body := `{
		"name": "Prueba",
		"surname": "Registro",
		"email": "registro-sin-2fa@example.com",
		"auth_key": "` + authKey + `",
		"dni": "12345678Z",
		"public_key": "fake",
		"signing_public_key": "fake",
		"private_key_bundle": {
			"version": 2,
			"algorithm": "AES-256-GCM",
			"kdf": "PBKDF2-HMAC-SHA256+HMAC-SHA256",
			"iterations": 600000,
			"salt": "` + salt + `",
			"nonce": "` + nonce + `",
			"ciphertext": "` + ciphertext + `"
		}
	}`

	request := httptest.NewRequest(
		http.MethodPost,
		"/register",
		bytes.NewBufferString(body),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400, recibido %d con cuerpo %q", response.Code, response.Body.String())
	}
	if response.Body.Len() == 0 {
		t.Fatal("el registro no debe terminar con una respuesta vacía")
	}
	if !strings.Contains(response.Body.String(), "claves criptográficas") {
		t.Fatalf("respuesta inesperada: %s", response.Body.String())
	}
}
