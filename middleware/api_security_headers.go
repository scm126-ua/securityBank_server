package middleware

import "github.com/gin-gonic/gin"

// Evita que las respuestas de la API (tokens, claves envueltas, documentos
// cifrados) se guarden en cachés del navegador o intermedias, y que el
// navegador interprete su contenido con un tipo distinto del declarado.
func APISecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Next()
	}
}
