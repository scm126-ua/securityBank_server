package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Limita las peticiones de cada usuario autenticado (token bucket) para frenar
// abusos como subidas masivas o descargas en bucle. Va detrás de AuthMiddleware.
// Guarda un limitador por usuario: crece con el número de usuarios, no de peticiones.
func UserRateLimit(requestsPerMinute int, burst int) gin.HandlerFunc {
	var mu sync.Mutex
	limiters := make(map[int64]*rate.Limiter)
	interval := time.Minute / time.Duration(requestsPerMinute)

	return func(c *gin.Context) {
		userID := c.GetInt64("userID")

		mu.Lock()
		limiter, exists := limiters[userID]
		if !exists {
			limiter = rate.NewLimiter(rate.Every(interval), burst)
			limiters[userID] = limiter
		}
		mu.Unlock()

		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Demasiadas peticiones. Espera un momento.",
			})
			return
		}

		c.Next()
	}
}
