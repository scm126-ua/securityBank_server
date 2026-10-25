package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

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

		// Aqui extraemos los datos del login y los validamos
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Datos de login inválidos",
			})
			return
		}

		// Llamamos al servicio de login
		user, err := userService.Login(
			c.Request.Context(),
			input.Email,
			input.Password,
		)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Credenciales incorrectas",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
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

		// Llamamos al servicio de login
		user, err := userService.Register(
			c.Request.Context(),
			input.Email,
			input.Password,
			input.Name,
			input.Surname,
		)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Credenciales incorrectas " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"user":   user,
		})

	}
}
