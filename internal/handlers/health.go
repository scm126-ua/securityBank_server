// Package handlers contiene los manejadores HTTP de la API.
package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"securityBank_server/internal/database"
)

// Health responde a GET /api/health: indica que el backend está en marcha.
// No consulta la base de datos (para eso está GET /api/health/db).
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// HealthDB responde a GET /api/health/db: comprueba que PostgreSQL responde y
// que existen las tablas del esquema.
//
// El detalle de los errores solo se registra en el servidor, no se envía al
// cliente, para no revelar información interna.
func HealthDB(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		if err := database.Ping(ctx, db); err != nil {
			log.Printf("health/db: PostgreSQL no responde: %v", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "database": "unavailable"})
			return
		}

		missing, err := database.MissingTables(ctx, db)
		if err != nil {
			log.Printf("health/db: no se pudo comprobar el esquema: %v", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "database": "unavailable"})
			return
		}
		if len(missing) > 0 {
			log.Printf("health/db: faltan tablas en la base de datos: %v", missing)
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "database": "ok", "schema": "incomplete"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok", "database": "ok", "schema": "ok"})
	}
}
