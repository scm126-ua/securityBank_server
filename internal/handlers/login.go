package handlers

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"securityBank_server/internal/services"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Surname  string `json:"surname" binding:"required"`
	DNI      string `json:"dni" binding:"required"`
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

func Register(
	userService *services.UserService,
	accountService *services.AccountService) gin.HandlerFunc {
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
		user, err := userService.Register(
			c.Request.Context(),
			input.Email,
			input.Password,
			input.Name,
			input.Surname,
			input.DNI,
		)

		// Creamos una cuenta por defecto para el usuario
		account, err := accountService.CreateAccount(c, user)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Credenciales incorrectas " + err.Error(),
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
