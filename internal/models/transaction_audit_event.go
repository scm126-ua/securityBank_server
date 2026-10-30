package models

import "time"

// Constantes de auditoría de transacciones.
// Action coincide con el tipo de operación intentada.
// Result indica si la operación se completó, fue denegada o falló.
// Reason solo se rellena cuando Result != SUCCESS.
const (
	TransactionAuditActionDeposit    = "DEPOSIT"
	TransactionAuditActionWithdrawal = "WITHDRAWAL"
	TransactionAuditActionTransfer   = "TRANSFER"

	TransactionAuditResultSuccess = "SUCCESS"
	TransactionAuditResultDenied  = "DENIED"
	TransactionAuditResultError   = "ERROR"

	TransactionAuditReasonInsufficientBalance = "INSUFFICIENT_BALANCE"
	TransactionAuditReasonAccountNotFound     = "ACCOUNT_NOT_FOUND"
	TransactionAuditReasonAccountClosed       = "ACCOUNT_CLOSED"
	TransactionAuditReasonUnauthorized        = "UNAUTHORIZED"
	TransactionAuditReasonInvalidAmount       = "INVALID_AMOUNT"
	TransactionAuditReasonSameAccount         = "SAME_ACCOUNT"
	TransactionAuditReasonDuplicateOperation  = "DUPLICATE_OPERATION"
)

// TransactionAuditEvent representa la tabla transaction_audit_events.
//
// Es de solo lectura después de la inserción: un trigger de PostgreSQL
// (reject_audit_event_changes) rechaza cualquier UPDATE o DELETE.
// Los punteros marcan columnas que admiten NULL (nil = NULL en la BD).
type TransactionAuditEvent struct {
	ID                   int64     `gorm:"column:id;primaryKey" json:"id"`
	UserID               int64     `gorm:"column:user_id" json:"user_id"`
	AccountID            *int64    `gorm:"column:account_id" json:"account_id"`
	TransactionReference *string   `gorm:"column:transaction_reference" json:"transaction_reference"`
	Action               string    `gorm:"column:action" json:"action"`
	Result               string    `gorm:"column:result" json:"result"`
	Reason               *string   `gorm:"column:reason" json:"reason"`
	CreatedAt            time.Time `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`
}

// TableName indica a GORM el nombre de la tabla.
func (TransactionAuditEvent) TableName() string { return "transaction_audit_events" }

