package handlers

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"securityBank_server/internal/services"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Email            string                  `json:"email" binding:"required,email"`
	Password         string                  `json:"password" binding:"required"`
	Name             string                  `json:"name" binding:"required"`
	Surname          string                  `json:"surname" binding:"required"`
	DNI              string                  `json:"dni" binding:"required"`
	PublicKey        string                  `json:"public_key" binding:"required"`
	SigningPublicKey string                  `json:"signing_public_key" binding:"required"`
	PrivateKeyBundle PrivateKeyBundleRequest `json:"private_key_bundle" binding:"required"`
}

type PrivateKeyBundleRequest struct {
	Version    int16  `json:"version" binding:"required"`
	Algorithm  string `json:"algorithm" binding:"required"`
	KDF        string `json:"kdf" binding:"required"`
	Iterations int    `json:"iterations" binding:"required"`
	Salt       string `json:"salt" binding:"required"`
	Nonce      string `json:"nonce" binding:"required"`
	Ciphertext string `json:"ciphertext" binding:"required"`
}

func Login(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input LoginRequest

		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Datos de login inválidos",
			})
			return
		}

		user, err := userService.Login(
			c.Request.Context(),
			input.Email,
			input.Password,
		)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Correo o contraseña incorrectos",
			})
			return
		}

		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "JWT_SECRET no está configurado",
			})
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": user.ID,
			"iat":     time.Now().Unix(),
			"exp":     time.Now().Add(time.Hour).Unix(),
		})

		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudo generar el token",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"token":  tokenString,
			"user":   user,
		})
	}
}

func Register(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input RegisterRequest

		// Aqui extraemos los datos del registro y los validamos
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Datos de registro inválidos " + err.Error(),
			})
			return
		}

		// Llamamos al servicio de registro
		user, account, err := userService.Register(
			c.Request.Context(),
			input.Email,
			input.Password,
			input.Name,
			input.Surname,
			input.DNI,
			services.UserKeyMaterial{
				PublicKey:        input.PublicKey,
				SigningPublicKey: input.SigningPublicKey,
				PrivateKeys: services.PrivateKeyBundle{
					Version:    input.PrivateKeyBundle.Version,
					Algorithm:  input.PrivateKeyBundle.Algorithm,
					KDF:        input.PrivateKeyBundle.KDF,
					Iterations: input.PrivateKeyBundle.Iterations,
					Salt:       input.PrivateKeyBundle.Salt,
					Nonce:      input.PrivateKeyBundle.Nonce,
					Ciphertext: input.PrivateKeyBundle.Ciphertext,
				},
			},
		)
		switch {
		case errors.Is(err, services.ErrInvalidEmail):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "El correo electrónico no es válido",
			})
			return
		case errors.Is(err, services.ErrInvalidPassword):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "La contraseña no es válida",
			})
			return
		case errors.Is(err, services.ErrInvalidDNI):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "El DNI no es válido",
			})
			return
		case errors.Is(err, services.ErrInvalidKeyMaterial):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Las claves criptográficas no son válidas",
			})
			return
		case errors.Is(err, services.ErrEmailExists):
			c.JSON(http.StatusConflict, gin.H{
				"error": "El correo electrónico ya está registrado",
			})
			return
		case errors.Is(err, services.ErrDNIExists):
			c.JSON(http.StatusConflict, gin.H{
				"error": "El DNI ya está registrado",
			})
			return
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudo completar el registro",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"user":    user,
			"account": account,
		})

	}
}
