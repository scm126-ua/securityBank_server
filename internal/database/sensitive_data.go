// Package database gestiona la conexión con PostgreSQL mediante GORM.
package database

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"securityBank_server/internal/models"
)

// sensitiveDataBackfillLockID serializa el backfill entre varios backends que
// arranquen a la vez. Es un identificador arbitrario y estable.
const sensitiveDataBackfillLockID int64 = 20261031

// SensitiveDataBackfillResult indica cuántos registros heredados se cifraron.
type SensitiveDataBackfillResult struct {
	Users    int64
	Accounts int64
}

type legacyUserValue struct {
	ID  int64                  `gorm:"column:id"`
	DNI models.EncryptedString `gorm:"column:dni"`
}

type legacyAccountValue struct {
	ID   int64                  `gorm:"column:id"`
	IBAN models.EncryptedString `gorm:"column:iban"`
}

// BackfillSensitiveData cifra los DNI e IBAN que aún están en texto plano y
// calcula su blind index. La migración 000011 convierte las columnas a BYTEA
// pero no puede cifrar su contenido: PostgreSQL no conoce DATA_ENCRYPTION_KEY.
// Por eso el propio backend completa la migración al arrancar.
//
// Es idempotente: solo procesa filas con dni_hash/iban_hash NULL. Si un valor
// cifrado no se puede descifrar (clave incorrecta o manipulación), devuelve
// error y el backend no arranca, en lugar de volver a cifrar datos corruptos.
func BackfillSensitiveData(
	ctx context.Context,
	db *gorm.DB,
) (SensitiveDataBackfillResult, error) {
	var result SensitiveDataBackfillResult

	if len(models.GetDataEncryptionKey()) != 32 {
		return result, models.ErrDataEncryptionKeyNotConfigured
	}

	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// El lock se libera automáticamente al terminar la transacción.
		if err := tx.Exec(
			"SELECT pg_advisory_xact_lock(?)",
			sensitiveDataBackfillLockID,
		).Error; err != nil {
			return fmt.Errorf("no se pudo bloquear el backfill de datos sensibles: %w", err)
		}

		var users []legacyUserValue
		if err := tx.Table("users").
			Select("id, dni").
			Where("dni_hash IS NULL").
			Order("id").
			Find(&users).Error; err != nil {
			return fmt.Errorf("no se pudieron leer los DNI heredados: %w", err)
		}

		for _, user := range users {
			dni := models.NormalizeSensitiveValue(string(user.DNI))
			if dni == "" {
				return fmt.Errorf("el usuario %d no tiene un DNI válido que cifrar", user.ID)
			}

			hash := models.HashBlindIndex(models.GetDataEncryptionKey(), dni)
			if hash == "" {
				return errors.New("no se pudo calcular el blind index del DNI")
			}

			update := tx.Exec(
				`UPDATE users
				    SET dni = ?, dni_hash = ?
				  WHERE id = ? AND dni_hash IS NULL`,
				models.EncryptedString(dni),
				hash,
				user.ID,
			)
			if update.Error != nil {
				return fmt.Errorf("no se pudo cifrar el DNI del usuario %d: %w", user.ID, update.Error)
			}
			result.Users += update.RowsAffected
		}

		var accounts []legacyAccountValue
		if err := tx.Table("accounts").
			Select("id, iban").
			Where("iban_hash IS NULL").
			Order("id").
			Find(&accounts).Error; err != nil {
			return fmt.Errorf("no se pudieron leer los IBAN heredados: %w", err)
		}

		for _, account := range accounts {
			iban := models.NormalizeSensitiveValue(string(account.IBAN))
			if iban == "" {
				return fmt.Errorf("la cuenta %d no tiene un IBAN válido que cifrar", account.ID)
			}

			hash := models.HashBlindIndex(models.GetDataEncryptionKey(), iban)
			if hash == "" {
				return errors.New("no se pudo calcular el blind index del IBAN")
			}

			update := tx.Exec(
				`UPDATE accounts
				    SET iban = ?, iban_hash = ?
				  WHERE id = ? AND iban_hash IS NULL`,
				models.EncryptedString(iban),
				hash,
				account.ID,
			)
			if update.Error != nil {
				return fmt.Errorf("no se pudo cifrar el IBAN de la cuenta %d: %w", account.ID, update.Error)
			}
			result.Accounts += update.RowsAffected
		}

		return nil
	})

	return result, err
}

// VerifySensitiveDataKey comprueba que la clave configurada puede descifrar
// datos existentes. Evita arrancar con una DATA_ENCRYPTION_KEY equivocada y
// servir errores 500 en cada consulta. Si la tabla aún está vacía no hay nada
// que verificar.
func VerifySensitiveDataKey(ctx context.Context, db *gorm.DB) error {
	if len(models.GetDataEncryptionKey()) != 32 {
		return models.ErrDataEncryptionKeyNotConfigured
	}

	var user legacyUserValue
	userResult := db.WithContext(ctx).
		Table("users").
		Select("id, dni").
		Where("dni_hash IS NOT NULL").
		Order("id").
		Limit(1).
		Find(&user)
	if userResult.Error != nil {
		return fmt.Errorf("no se pudo verificar la clave de los DNI existentes: %w", userResult.Error)
	}

	var account legacyAccountValue
	accountResult := db.WithContext(ctx).
		Table("accounts").
		Select("id, iban").
		Where("iban_hash IS NOT NULL").
		Order("id").
		Limit(1).
		Find(&account)
	if accountResult.Error != nil {
		return fmt.Errorf("no se pudo verificar la clave de los IBAN existentes: %w", accountResult.Error)
	}

	return nil
}
