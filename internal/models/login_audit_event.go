package models

import "time"

// Valores permitidos para el resultado de un intento de inicio de sesión.
const (
	LoginAuditResultSuccessful      = "SUCCESSFUL"
	LoginAuditResultFailed          = "FAILED"
	LoginAuditResultAccountNotFound = "ACCOUNT_NOT_FOUND"
)

// LoginAuditEvent representa un intento de inicio de sesión.
//
// Es append-only: un trigger de PostgreSQL rechaza cualquier UPDATE o DELETE.
// No contiene credenciales; solo el email intentado, el origen de la petición
// y el resultado.
type LoginAuditEvent struct {
	ID        int64     `gorm:"column:id;primaryKey" json:"id"`
	UserID    *int64    `gorm:"column:user_id" json:"user_id"`
	Email     string    `gorm:"column:email" json:"email"`
	IPAddress string    `gorm:"column:ip_address" json:"ip_address"`
	UserAgent string    `gorm:"column:user_agent" json:"user_agent"`
	Result    string    `gorm:"column:result" json:"result"`
	CreatedAt time.Time `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`
}

// TableName indica a GORM la tabla que almacena la auditoría de login.
func (LoginAuditEvent) TableName() string { return "login_audit_events" }
