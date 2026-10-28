package models

import "time"

// Valores permitidos para User.Role (CHECK de users.role).
const (
	UserRoleClient = "CLIENT"
	UserRoleAdmin  = "ADMIN"
)

// User representa la tabla users.
//
// Solo se guardan claves públicas: las claves privadas nunca se almacenan
// sin cifrar.
type User struct {
	ID           int64  `gorm:"column:id;primaryKey" json:"id"`
	Name         string `gorm:"column:name" json:"name"`
	DNI          string `gorm:"column:dni" json:"dni"`
	Email        string `gorm:"column:email" json:"email"`
	PasswordHash string `gorm:"column:password_hash" json:"-"` // json:"-": nunca se envía en las respuestas
	Salt         string `gorm:"column:salt" json:"-"`
	Role         string `gorm:"column:role" json:"role"`
	// NULL hasta completar el registro criptográfico.
	PublicKey *string `gorm:"column:public_key" json:"public_key"`
	// Clave pública para verificar las firmas digitales del usuario.
	SigningPublicKey *string `gorm:"column:signing_public_key" json:"signing_public_key"`
	// Firma del servidor que vincula el correo con las dos claves públicas.
	PublicKeysSignature   *string   `gorm:"column:public_keys_signature" json:"public_keys_signature"`
	EncryptedPrivateKeys  []byte    `gorm:"column:encrypted_private_keys" json:"-"`
	PrivateKeysSalt       []byte    `gorm:"column:private_keys_salt" json:"-"`
	PrivateKeysNonce      []byte    `gorm:"column:private_keys_nonce" json:"-"`
	PrivateKeysIterations *int      `gorm:"column:private_keys_iterations" json:"-"`
	PrivateKeysVersion    *int16    `gorm:"column:private_keys_version" json:"-"`
	CreatedAt             time.Time `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`

	FailedLoginAttempts    int        `gorm:"not null;default:0" json:"-"`
	LastFailedLoginAttempt *time.Time `gorm:"column:last_failed_login_attempt" json:"-"`
	LockedUntil            *time.Time `gorm:"column:locked_until" json:"-"`
	
	// Relaciones
	AccountUsers   []AccountUser    `gorm:"foreignKey:UserID" json:"account_users,omitempty"`   // cuentas del usuario (N:M)
	Documents      []Document       `gorm:"foreignKey:OwnerID" json:"documents,omitempty"`      // documentos de los que es propietario
	DocumentAccess []DocumentAccess `gorm:"foreignKey:UserID" json:"document_access,omitempty"` // accesos a documentos
}

// TableName indica a GORM el nombre de la tabla.
func (User) TableName() string { return "users" }
