// Punto de entrada del backend de SecurityBank.
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"securityBank_server/internal/config"
	"securityBank_server/internal/database"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("error de configuración: %v", err)
	}

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("error de base de datos: %v", err)
	}
	log.Println("conexión con PostgreSQL establecida")

	router := gin.Default()

	// No hay ningún proxy delante del backend: no confiamos en cabeceras
	// como X-Forwarded-For para obtener la IP del cliente.
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("error configurando proxies de confianza: %v", err)
	}

	// CORS: solo el frontend de desarrollo puede llamar a la API desde el navegador.
	router.Use(cors.New(cors.Config{
		AllowOrigins: []string{cfg.CORSOrigin},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
		MaxAge:       12 * time.Hour,
	}))

	api := router.Group("/api")
	api.GET("/health", healthHandler(db))

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("backend escuchando en el puerto %s", cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("error del servidor HTTP: %v", err)
	}
}

// healthHandler responde con el estado de la aplicación y de la base de datos.
func healthHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := database.Ping(c.Request.Context(), db); err != nil {
			// El detalle del error solo se registra en el servidor, no se envía al cliente.
			log.Printf("health: PostgreSQL no responde: %v", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":   "error",
				"database": "unavailable",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":   "ok",
			"database": "ok",
		})
	}
}
