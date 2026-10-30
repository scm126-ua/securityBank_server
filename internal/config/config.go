// Package config lee la configuración del backend desde variables de entorno.
package config

import (
	"errors"
	"os"
)

// Config agrupa los valores de configuración que necesita el backend.
type Config struct {
	DatabaseURL       string // Cadena de conexión a PostgreSQL (DATABASE_URL).
	Port              string // Puerto HTTP interno del backend (BACKEND_PORT).
	CORSOrigin        string // Origen del frontend permitido por CORS (CORS_ORIGIN).
	ServerKeyPath     string // Ruta de la clave privada del servidor (SERVER_KEY_PATH).
	TOTPEncryptionKey string // Clave de cifrado para TOTP (TOTP_ENCRYPTION_KEY).
}

// Load lee la configuración. DATABASE_URL es obligatoria; el resto de
// variables tiene un valor por defecto pensado para desarrollo local.
func Load() (Config, error) {

	cfg := Config{
		DatabaseURL:       getEnv("DATABASE_URL", ""),
		Port:              getEnv("BACKEND_PORT", "8080"),
		CORSOrigin:        getEnv("CORS_ORIGIN", "https://localhost:8443"),
		ServerKeyPath:     getEnv("SERVER_KEY_PATH", ".keys/server_private.pem"),
		TOTPEncryptionKey: getEnv("TOTP_ENCRYPTION_KEY", "DuLMfen6unn7Nhmb3WMxo+xibIJS3LXo0dr3VaOcoMY="),
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
