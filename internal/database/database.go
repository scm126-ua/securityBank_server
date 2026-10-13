// Package database gestiona la conexión con PostgreSQL mediante GORM.
package database

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"securityBank_server/internal/models"
)

// pingTimeout es el tiempo máximo que esperamos a que PostgreSQL responda.
const pingTimeout = 3 * time.Second

// Connect abre la conexión con PostgreSQL y comprueba que la base de datos
// responde antes de devolverla.
//
// No se ejecuta AutoMigrate: el esquema lo crean las migraciones SQL de
// database/migrations/ (servicio "migrate" de compose.yaml).
func Connect(databaseURL string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{
		// Hacemos la comprobación nosotros mismos con Ping (y un timeout).
		DisableAutomaticPing: true,
	})
	if err != nil {
		return nil, fmt.Errorf("no se pudo configurar la conexión con PostgreSQL: %w", err)
	}

	if err := Ping(context.Background(), db); err != nil {
		return nil, fmt.Errorf("PostgreSQL no está disponible: %w", err)
	}

	return db, nil
}

// Ping comprueba que PostgreSQL está disponible.
func Ping(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	return sqlDB.PingContext(ctx)
}

// MissingTables devuelve las tablas de los modelos que no existen en la base
// de datos. Solo consulta el catálogo de PostgreSQL: no crea ni modifica nada.
func MissingTables(ctx context.Context, db *gorm.DB) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	var expected []string
	for _, model := range models.All() {
		expected = append(expected, model.TableName())
	}

	var existing []string
	err := db.WithContext(ctx).Raw(
		`SELECT table_name FROM information_schema.tables
		 WHERE table_schema = current_schema() AND table_name IN ?`,
		expected,
	).Scan(&existing).Error
	if err != nil {
		return nil, err
	}

	found := make(map[string]bool, len(existing))
	for _, name := range existing {
		found[name] = true
	}

	var missing []string
	for _, name := range expected {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	return missing, nil
}
