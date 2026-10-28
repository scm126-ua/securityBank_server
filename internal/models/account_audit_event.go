package models

import "time"

// Valores permitidos para la acción registrada.
const (
	AccountAuditActionCreate = "CREATE"
	AccountAuditActionClose  = "CLOSE"
)

// Valores permitidos para el resultado de la operación.
const (
	AccountAuditResultSuccess = "SUCCESS"
	AccountAuditResultDenied  = "DENIED"
	AccountAuditResultError   = "ERROR"
)

// Códigos permitidos para explicar un cierre rechazado.
const (
	AccountAuditReasonNotFound      = "ACCOUNT_NOT_FOUND"
	AccountAuditReasonNonZero       = "NON_ZERO_BALANCE"
	AccountAuditReasonAlreadyClosed = "ALREADY_CLOSED"
)

// Representa un evento inmutable de creación o cierre de una cuenta.
type AccountAuditEvent struct {
	ID        int64     `gorm:"column:id;primaryKey" json:"id"`
	UserID    int64     `gorm:"column:user_id" json:"user_id"`
	AccountID *int64    `gorm:"column:account_id" json:"account_id"`
	Action    string    `gorm:"column:action" json:"action"`
	Result    string    `gorm:"column:result" json:"result"`
	Reason    *string   `gorm:"column:reason" json:"reason"`
	CreatedAt time.Time `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`
}

// Indica a GORM la tabla que almacena los eventos de auditoría.
func (AccountAuditEvent) TableName() string { return "account_audit_events" }
