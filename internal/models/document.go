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
	GCMNonceSize = 12 // bytes de Document.Nonce y Document.MetadataNonce
	GCMTagSize   = 16 // bytes del tag al final de los datos cifrados
)

// Document representa la tabla documents.
//
// El cliente cifra el contenido y los metadatos con AES-256-GCM; el servidor
// nunca los ve en claro. Formato de los datos cifrados:
//
//	encrypted_content  = ciphertext || tag GCM (últimos 16 bytes)
//	nonce              = 12 bytes aleatorios del contenido
//	encrypted_metadata = metadatos rellenados a tamaño fijo || tag GCM
//	metadata_nonce     = 12 bytes aleatorios, distintos del nonce del contenido
type Document struct {
	ID                int64     `gorm:"column:id;primaryKey" json:"-"`
	PublicID          string    `gorm:"column:public_id" json:"id"`
	OwnerID           int64     `gorm:"column:owner_id" json:"owner_id"`
	Type              string    `gorm:"column:type" json:"type"`
	FormatVersion     int16     `gorm:"column:format_version" json:"format_version"`
	EncryptedContent  []byte    `gorm:"column:encrypted_content" json:"encrypted_content"`
	Nonce             []byte    `gorm:"column:nonce" json:"nonce"`
	EncryptedMetadata []byte    `gorm:"column:encrypted_metadata" json:"encrypted_metadata"`
	MetadataNonce     []byte    `gorm:"column:metadata_nonce" json:"metadata_nonce"`
	KeyCommitment     []byte    `gorm:"column:key_commitment" json:"key_commitment"`
	Signature         []byte    `gorm:"column:signature" json:"signature"`
	CreatedAt         time.Time `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`

	// Relaciones
	Owner  *User            `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`
	Access []DocumentAccess `gorm:"foreignKey:DocumentID" json:"access,omitempty"` // copias de la clave AES por usuario
}

// TableName indica a GORM el nombre de la tabla.
func (Document) TableName() string { return "documents" }
