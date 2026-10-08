// Package config lee la configuración del backend desde variables de entorno.
package config

import (
	"errors"
	"os"
)

// Config agrupa los valores de configuración que necesita el backend.
type Config struct {
	DatabaseURL string // Cadena de conexión a PostgreSQL (DATABASE_URL).
	Port        string // Puerto HTTP del backend (BACKEND_PORT).
	CORSOrigin  string // Origen del frontend permitido por CORS (CORS_ORIGIN).
}

// Load lee la configuración. DATABASE_URL es obligatoria; el resto de
// variables tiene un valor por defecto pensado para desarrollo local.
func Load() (Config, error) {
	cfg := Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		Port:        getEnv("BACKEND_PORT", "8080"),
		CORSOrigin:  getEnv("CORS_ORIGIN", "http://localhost:5173"),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("la variable de entorno DATABASE_URL es obligatoria")
	}

	return cfg, nil
}

// getEnv devuelve el valor de la variable key o fallback si no está definida.
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
