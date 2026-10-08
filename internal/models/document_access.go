package models

// Valores permitidos para DocumentAccess.Permission (CHECK de document_access.permission).
const (
	DocumentPermissionOwner = "OWNER"
	DocumentPermissionRead  = "READ"
	DocumentPermissionShare = "SHARE"
)

// DocumentAccess representa la tabla document_access: una copia de la clave
// AES del documento cifrada con la clave pública (users.public_key) de cada
// usuario autorizado.
//
// Primary key compuesta (document_id, user_id). autoIncrement:false evita que
// GORM trate estas columnas como autoincrementales.
type DocumentAccess struct {
	DocumentID      int64  `gorm:"column:document_id;primaryKey;autoIncrement:false" json:"document_id"`
	UserID          int64  `gorm:"column:user_id;primaryKey;autoIncrement:false" json:"user_id"`
	EncryptedAESKey []byte `gorm:"column:encrypted_aes_key" json:"encrypted_aes_key"`
	Permission      string `gorm:"column:permission;default:OWNER" json:"permission"`
	Revoked         bool   `gorm:"column:revoked" json:"revoked"`

	// Relaciones
	Document *Document `gorm:"foreignKey:DocumentID" json:"document,omitempty"`
	User     *User     `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName indica a GORM el nombre de la tabla.
func (DocumentAccess) TableName() string { return "document_access" }
