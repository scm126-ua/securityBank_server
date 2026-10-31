package repositories

import (
	"context"

	"gorm.io/gorm"

	"securityBank_server/internal/models"
)

// LoginAuditRepository guarda los intentos de inicio de sesión.
//
// La tabla es append-only: este repositorio solo expone la inserción para no
// dar la falsa impresión de que los eventos se pueden modificar.
type LoginAuditRepository struct {
	db *gorm.DB
}

func NewLoginAuditRepository(db *gorm.DB) *LoginAuditRepository {
	return &LoginAuditRepository{db: db}
}

// Record inserta un nuevo evento de auditoría de login.
func (r *LoginAuditRepository) Record(
	ctx context.Context,
	event *models.LoginAuditEvent,
) error {
	return r.db.WithContext(ctx).Create(event).Error
}
