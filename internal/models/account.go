package models

import (
	"time"

	"github.com/shopspring/decimal"
)

// Valores permitidos para Account.Status (CHECK de accounts.status).
const (
	AccountStatusActive = "ACTIVE"
	AccountStatusClosed = "CLOSED"
)

// Account representa la tabla accounts (cuentas bancarias simuladas).
type Account struct {
	ID   int64  `gorm:"column:id;primaryKey" json:"id"`
	IBAN string `gorm:"column:iban" json:"iban"`
	// NUMERIC(18,2): decimal exacto. No puede ser negativo (CHECK en SQL).
	Balance   decimal.Decimal `gorm:"column:balance" json:"balance"`
	Status    string          `gorm:"column:status;default:ACTIVE" json:"status"`
	CreatedAt time.Time       `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`

	// Relaciones
	AccountUsers         []AccountUser `gorm:"foreignKey:AccountID" json:"account_users,omitempty"`                    // usuarios de la cuenta (N:M)
	OutgoingTransactions []Transaction `gorm:"foreignKey:SourceAccountID" json:"outgoing_transactions,omitempty"`      // movimientos con esta cuenta como origen
	IncomingTransactions []Transaction `gorm:"foreignKey:DestinationAccountID" json:"incoming_transactions,omitempty"` // movimientos con esta cuenta como destino
}

// TableName indica a GORM el nombre de la tabla.
func (Account) TableName() string { return "accounts" }
