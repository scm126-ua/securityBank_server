package models

import "time"

// Valores permitidos para DocumentAccess.Permission (CHECK de document_access.permission).
const (
	DocumentPermissionOwner = "OWNER" // descargar, compartir y eliminar
	DocumentPermissionRead  = "READ"  // solo descargar
	DocumentPermissionShare = "SHARE" // descargar y volver a compartir con permiso READ
)

// Algoritmo con el que se envuelve la clave AES de cada documento.
const DocumentKeyAlgorithmRSAOAEP3072 = "RSA-OAEP-3072-SHA256"

// DocumentAccess representa la tabla document_access: una copia de la clave
// AES del documento cifrada con la clave pública (users.public_key) de cada
// usuario autorizado.
//
// Primary key compuesta (document_id, user_id). autoIncrement:false evita que
// GORM trate estas columnas como autoincrementales.
type DocumentAccess struct {
	DocumentID      int64      `gorm:"column:document_id;primaryKey;autoIncrement:false" json:"document_id"`
	UserID          int64      `gorm:"column:user_id;primaryKey;autoIncrement:false" json:"user_id"`
	EncryptedAESKey []byte     `gorm:"column:encrypted_aes_key" json:"encrypted_aes_key"`
	KeyAlgorithm    string     `gorm:"column:key_algorithm;default:RSA-OAEP-3072-SHA256" json:"key_algorithm"`
	Permission      string     `gorm:"column:permission;default:OWNER" json:"permission"`
	Revoked         bool       `gorm:"column:revoked" json:"revoked"`
	GrantedBy       int64      `gorm:"column:granted_by" json:"granted_by"`
	GrantedAt       time.Time  `gorm:"column:granted_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"granted_at"`
	RevokedAt       *time.Time `gorm:"column:revoked_at" json:"revoked_at"`

	// Relaciones
	Document *Document `gorm:"foreignKey:DocumentID" json:"document,omitempty"`
	User     *User     `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName indica a GORM el nombre de la tabla.
func (DocumentAccess) TableName() string { return "document_access" }
