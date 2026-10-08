package models

import "time"

// Valores permitidos para Document.Type (CHECK de documents.type).
const (
	DocumentTypeStatement            = "STATEMENT"
	DocumentTypeTransactionReceipt   = "TRANSACTION_RECEIPT"
	DocumentTypeOwnershipCertificate = "OWNERSHIP_CERTIFICATE"
	DocumentTypePersonal             = "PERSONAL"
)

// Tamaños de AES-256-GCM (también comprobados con CHECK en SQL).
const (
	GCMNonceSize = 12 // bytes de Document.Nonce
	GCMTagSize   = 16 // bytes del tag al final de Document.EncryptedContent
)

// Document representa la tabla documents.
//
// El cliente cifra el contenido con AES-256-GCM; el servidor nunca lo ve en
// claro. Formato de EncryptedContent:
//
//	encrypted_content = ciphertext || tag GCM (últimos 16 bytes)
//	nonce             = 12 bytes aleatorios, distintos en cada cifrado
type Document struct {
	ID               int64     `gorm:"column:id;primaryKey" json:"id"`
	OwnerID          int64     `gorm:"column:owner_id" json:"owner_id"`
	Type             string    `gorm:"column:type" json:"type"`
	EncryptedContent []byte    `gorm:"column:encrypted_content" json:"encrypted_content"`
	Nonce            []byte    `gorm:"column:nonce" json:"nonce"`
	CreatedAt        time.Time `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`

	// Relaciones
	Owner  *User            `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`
	Access []DocumentAccess `gorm:"foreignKey:DocumentID" json:"access,omitempty"` // copias de la clave AES por usuario
}

// TableName indica a GORM el nombre de la tabla.
func (Document) TableName() string { return "documents" }
