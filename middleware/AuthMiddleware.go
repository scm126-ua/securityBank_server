package middleware

import (
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"securityBank_server/internal/services"
)

// Cookie HttpOnly que transporta el JWT de sesión: JavaScript no puede leerla.
const SessionCookieName = "securitybank_session"

func AuthMiddleware(serverPublicKey *rsa.PublicKey, revokedTokens *services.RevokedTokens) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie(SessionCookieName)
		if err != nil || tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Usuario no autenticado",
			})
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodRS256 {
				return nil, fmt.Errorf("algoritmo JWT no permitido: %v", token.Header["alg"])
			}

			return serverPublicKey, nil
		})

		if err != nil {
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

		// Un token de una sesión cerrada no se acepta aunque todavía no haya caducado.
		tokenID, _ := claims["jti"].(string)
		expiresAt, err := claims.GetExpirationTime()
		if tokenID == "" || err != nil || expiresAt == nil || revokedTokens.IsRevoked(tokenID) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Token inválido o expirado",
			})
			return
		}

		c.Set("userID", int64(userID))
		c.Set("tokenID", tokenID)
		c.Set("tokenExpiresAt", expiresAt.Time)
		c.Next()
	}
}
