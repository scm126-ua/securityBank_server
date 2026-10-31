package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	"securityBank_server/internal/models"
)

// Guarda los tres estados posibles y comprueba que se conservan el email, el
// origen de la petición y el timestamp.
func TestRecordLoginAuditEvents(t *testing.T) {
	db := connectIntegrationDB(t)
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("no se pudo iniciar la transacción de prueba: %v", tx.Error)
	}
	defer rollback(t, tx)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := createSecurityTestUser(t, tx, "login", suffix)
	repo := NewLoginAuditRepository(tx)

	events := []*models.LoginAuditEvent{
		{
			UserID:    &user.ID,
			Email:     user.Email,
			IPAddress: "203.0.113.10",
			UserAgent: "Mozilla/5.0 (prueba)",
			Result:    models.LoginAuditResultSuccessful,
		},
		{
			UserID:    &user.ID,
			Email:     user.Email,
			IPAddress: "203.0.113.11",
			UserAgent: "Mozilla/5.0 (prueba)",
			Result:    models.LoginAuditResultFailed,
		},
		{
			UserID:    nil,
			Email:     "no-existe-" + suffix + "@securitybank.test",
			IPAddress: "2001:db8::1",
			UserAgent: "",
			Result:    models.LoginAuditResultAccountNotFound,
		},
	}

	before := time.Now().Add(-time.Minute)
	for _, event := range events {
		if err := repo.Record(context.Background(), event); err != nil {
			t.Fatalf("no se pudo guardar el evento de auditoría: %v", err)
		}
	}

	var stored []models.LoginAuditEvent
	if err := tx.Order("id").Find(&stored).Error; err != nil {
		t.Fatalf("no se pudieron leer los eventos guardados: %v", err)
	}
	if len(stored) != len(events) {
		t.Fatalf("se esperaban %d eventos, hay %d", len(events), len(stored))
	}

	for i, expected := range events {
		got := stored[i]
		if got.Email != expected.Email || got.Result != expected.Result {
			t.Fatalf("evento %d inesperado: %+v", i, got)
		}
		if got.IPAddress != expected.IPAddress || got.UserAgent != expected.UserAgent {
			t.Fatalf("origen inesperado en el evento %d: %+v", i, got)
		}
		if expected.UserID == nil {
			if got.UserID != nil {
				t.Fatalf("el evento %d no debería tener usuario: %+v", i, got)
			}
		} else if got.UserID == nil || *got.UserID != *expected.UserID {
			t.Fatalf("usuario inesperado en el evento %d: %+v", i, got)
		}
		if got.CreatedAt.Before(before) || got.CreatedAt.After(time.Now().Add(time.Minute)) {
			t.Fatalf("timestamp inesperado en el evento %d: %v", i, got.CreatedAt)
		}
	}
}

// La auditoría de login debe ser append-only, igual que el resto.
func TestLoginAuditEventsAreAppendOnly(t *testing.T) {
	db := connectIntegrationDB(t)
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("no se pudo iniciar la transacción de prueba: %v", tx.Error)
	}
	defer rollback(t, tx)

	repo := NewLoginAuditRepository(tx)
	if err := repo.Record(context.Background(), &models.LoginAuditEvent{
		Email:     "append-only@securitybank.test",
		IPAddress: "203.0.113.20",
		Result:    models.LoginAuditResultFailed,
	}); err != nil {
		t.Fatalf("no se pudo insertar el evento inicial: %v", err)
	}

	if err := tx.SavePoint("login_audit_delete").Error; err != nil {
		t.Fatalf("no se pudo crear el savepoint: %v", err)
	}
	if err := tx.Exec("DELETE FROM login_audit_events").Error; err == nil {
		t.Fatal("el trigger debería impedir borrar eventos de auditoría")
	}
	if err := tx.RollbackTo("login_audit_delete").Error; err != nil {
		t.Fatalf("no se pudo recuperar la transacción: %v", err)
	}

	var count int64
	if err := tx.Model(&models.LoginAuditEvent{}).Count(&count).Error; err != nil {
		t.Fatalf("no se pudo contar los eventos: %v", err)
	}
	if count != 1 {
		t.Fatalf("el evento de auditoría desapareció: count=%d", count)
	}
}
