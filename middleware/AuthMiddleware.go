package middleware

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		parts := strings.SplitN(authHeader, " ", 2)

		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Usuario no autenticado",
			})
			return
		}

		// Leer el secreto al procesar la petición.
		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			fmt.Println("ERROR: JWT_SECRET no está configurado")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Configuración de autenticación incorrecta",
			})
			return
		}

		token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("algoritmo JWT no permitido: %v", token.Header["alg"])
			}

			return []byte(secret), nil
		})

		if err != nil {
			// Temporalmente, para diagnosticar el problema.
			fmt.Println("Error validando JWT:", err)

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Token inválido o expirado",
			})
			return
		}

		if !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Token inválido o expirado",
			})
			return
		}

		// CORRECCIÓN: MapClaims es un valor, no un puntero.
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Token inválido",
			})
			return
		}

		userID, ok := claims["user_id"].(float64)
		if !ok || userID <= 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "El token no contiene un user_id válido",
			})
			return
		}

		c.Set("userID", int64(userID))
		c.Next()
	}
}