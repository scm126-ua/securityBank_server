package repositories

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/gorm"

	"securityBank_server/internal/database"
	"securityBank_server/internal/models"
)

// Comprueba con PostgreSQL que un usuario no puede consultar ni cerrar una cuenta ajena.
func TestAccountAccessIsRestrictedToOwner(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no está disponible para la prueba de integración")
	}

	db, err := database.Connect(databaseURL)
	if err != nil {
		t.Fatalf("no se pudo conectar con la base de datos de prueba: %v", err)
	}

	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("no se pudo iniciar la transacción de prueba: %v", tx.Error)
	}
	defer func() {
		if err := tx.Rollback().Error; err != nil {
			t.Errorf("no se pudo revertir la transacción de prueba: %v", err)
		}
	}()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner := createSecurityTestUser(t, tx, "owner", suffix)
	intruder := createSecurityTestUser(t, tx, "intruder", suffix)
	account, err := createAccount(tx, owner.ID, "TEST"+suffix)
	if err != nil {
		t.Fatalf("no se pudo crear la cuenta de prueba: %v", err)
	}

	repository := NewAccountRepository(tx)
	ownership, err := repository.FindOwnership(context.Background(), owner.ID, account.ID)
	if err != nil || ownership.HolderID != owner.ID {
		t.Fatalf("el propietario no pudo consultar su titularidad: %v", err)
	}

	_, err = repository.FindOwnership(context.Background(), intruder.ID, account.ID)
	if !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("la consulta ajena no fue rechazada: %v", err)
	}

	_, err = repository.Close(context.Background(), intruder.ID, account.ID)
	if !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("el cierre ajeno no fue rechazado: %v", err)
	}

	var storedAccount models.Account
	if err := tx.First(&storedAccount, account.ID).Error; err != nil {
		t.Fatalf("no se pudo recuperar la cuenta de prueba: %v", err)
	}
	if storedAccount.Status != models.AccountStatusActive {
		t.Fatal("el intento ajeno modificó el estado de la cuenta")
	}

	var auditEvent models.AccountAuditEvent
	err = tx.Where(
		"user_id = ? AND account_id = ? AND action = ? AND result = ?",
		intruder.ID,
		account.ID,
		models.AccountAuditActionClose,
		models.AccountAuditResultDenied,
	).First(&auditEvent).Error
	if err != nil || auditEvent.Reason == nil ||
		*auditEvent.Reason != models.AccountAuditReasonNotFound {
		t.Fatalf("el acceso rechazado no quedó auditado correctamente: %v", err)
	}
}

// Inserta un usuario mínimo y único dentro de la transacción de prueba.
func createSecurityTestUser(
	t *testing.T,
	tx *gorm.DB,
	prefix string,
	suffix string,
) *models.User {
	t.Helper()

	user := &models.User{
		Name:         prefix + " security test",
		DNI:          models.EncryptedString(prefix[:1] + suffix),
		Email:        prefix + "-" + suffix + "@securitybank.test",
		PasswordHash: "test-password-hash",
		Salt:         "test-salt",
		Role:         models.UserRoleClient,
	}

	if err := tx.Create(user).Error; err != nil {
		t.Fatalf("no se pudo crear el usuario de prueba: %v", err)
	}

	return user
}
