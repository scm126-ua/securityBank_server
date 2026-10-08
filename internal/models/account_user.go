package models

// Valores permitidos para AccountUser.Role (CHECK de account_users.role).
const (
	AccountRoleOwner      = "OWNER"
	AccountRoleCoOwner    = "CO_OWNER"
	AccountRoleAuthorized = "AUTHORIZED"
)

// AccountUser representa la tabla account_users: la relación N:M entre
// usuarios y cuentas.
//
// Se modela como una entidad propia (y no con many2many de GORM) porque la
// relación tiene su propia columna, role, que GORM no rellenaría.
//
// Primary key compuesta (user_id, account_id). autoIncrement:false evita que
// GORM trate estas columnas como autoincrementales.
type AccountUser struct {
	UserID    int64  `gorm:"column:user_id;primaryKey;autoIncrement:false" json:"user_id"`
	AccountID int64  `gorm:"column:account_id;primaryKey;autoIncrement:false" json:"account_id"`
	Role      string `gorm:"column:role" json:"role"`

	// Relaciones
	User    *User    `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Account *Account `gorm:"foreignKey:AccountID" json:"account,omitempty"`
}

// TableName indica a GORM el nombre de la tabla.
func (AccountUser) TableName() string { return "account_users" }
