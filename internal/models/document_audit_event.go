package models

import "time"

// Acciones registradas sobre documentos. SHARE y REVOKE quedan reservadas
// para la futura compartición.
const (
	DocumentAuditActionUpload   = "UPLOAD"
	DocumentAuditActionDownload = "DOWNLOAD"
	DocumentAuditActionDelete   = "DELETE"
	DocumentAuditActionShare    = "SHARE"
	DocumentAuditActionRevoke   = "REVOKE"
)

// Valores permitidos para el resultado de la operación.
const (
	DocumentAuditResultSuccess = "SUCCESS"
	DocumentAuditResultDenied  = "DENIED"
	DocumentAuditResultError   = "ERROR"
)

// Códigos que explican un rechazo o un error sin revelar datos sensibles.
const (
	DocumentAuditReasonNotFound         = "DOCUMENT_NOT_FOUND"
	DocumentAuditReasonNotOwner         = "NOT_OWNER"
	DocumentAuditReasonInvalidSignature = "INVALID_SIGNATURE"
	DocumentAuditReasonQuotaExceeded    = "QUOTA_EXCEEDED"
	DocumentAuditReasonDuplicateID      = "DUPLICATE_ID"
	DocumentAuditReasonIntegrityFailure = "INTEGRITY_FAILURE"
)

// Representa un evento inmutable sobre un documento.
type DocumentAuditEvent struct {
	ID         int64     `gorm:"column:id;primaryKey" json:"id"`
	UserID     int64     `gorm:"column:user_id" json:"user_id"`
	DocumentID *string   `gorm:"column:document_id" json:"document_id"`
	Action     string    `gorm:"column:action" json:"action"`
	Result     string    `gorm:"column:result" json:"result"`
	Reason     *string   `gorm:"column:reason" json:"reason"`
	CreatedAt  time.Time `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`
}

// Indica a GORM la tabla que almacena los eventos de auditoría de documentos.
func (DocumentAuditEvent) TableName() string { return "document_audit_events" }
