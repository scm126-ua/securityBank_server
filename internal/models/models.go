// Package models contiene los modelos GORM de las tablas definidas en las
// migraciones de database/migrations/.
//
// El esquema lo crean las migraciones SQL, no GORM: los modelos solo describen
// cómo leer y escribir esas tablas y no se usa AutoMigrate. Si una migración
// cambia una tabla, actualiza también su modelo (y ejecuta los tests de este
// paquete).
//
// Convenciones:
//   - Cada campo indica su columna con la etiqueta gorm:"column:...".
//   - Las columnas que admiten NULL usan punteros (*string, *int64): nil = NULL.
//   - Las cantidades de dinero usan decimal.Decimal, nunca float32/float64.
//   - created_at lo asigna PostgreSQL (DEFAULT CURRENT_TIMESTAMP) y GORM lo
//     lee tras el INSERT; por eso se desactiva autoCreateTime.
//   - Los campos de relación solo se rellenan si se cargan con Preload.
package models

import "gorm.io/gorm/schema"

// All devuelve una instancia de cada modelo. Se usa para comprobar que las
// tablas existen en la base de datos.
func All() []schema.Tabler {
	return []schema.Tabler{
		&User{},
		&Account{},
		&AccountUser{},
		&Transaction{},
		&Document{},
		&DocumentAccess{},
	}
}
