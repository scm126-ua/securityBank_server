// Package database gestiona la conexión con PostgreSQL mediante GORM.
package database

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// pingTimeout es el tiempo máximo que esperamos a que PostgreSQL responda.
const pingTimeout = 3 * time.Second

// Connect abre la conexión con PostgreSQL y comprueba que la base de datos
// responde antes de devolverla.
//
// No se ejecuta AutoMigrate: el esquema se creará mediante scripts SQL.
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
