// Punto de entrada del backend de SecurityBank.
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"securityBank_server/internal/config"
	"securityBank_server/internal/database"
	"securityBank_server/internal/handlers"
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

	// Avisa si falta alguna tabla (por ejemplo, si no se han aplicado las migraciones).
	// No se crean tablas: el esquema solo se gestiona con las migraciones SQL.
	missing, err := database.MissingTables(context.Background(), db)
	switch {
	case err != nil:
		log.Printf("AVISO: no se pudo comprobar el esquema: %v", err)
	case len(missing) > 0:
		log.Printf("AVISO: faltan tablas en la base de datos: %v. Aplica las migraciones: docker compose run --rm migrate up (ver README).", missing)
	default:
		log.Println("esquema de la base de datos comprobado: todas las tablas existen")
	}

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
	api.GET("/health", handlers.Health)
	api.GET("/health/db", handlers.HealthDB(db))

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
