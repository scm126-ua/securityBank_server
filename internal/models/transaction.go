package models

import (
	"time"

	"github.com/shopspring/decimal"
)

// Valores permitidos para Transaction.Type (CHECK de transactions.type).
const (
	TransactionTypeDeposit    = "DEPOSIT"    // solo cuenta destino
	TransactionTypeWithdrawal = "WITHDRAWAL" // solo cuenta origen
	TransactionTypeTransfer   = "TRANSFER"   // cuenta origen y destino, distintas
)

// Transaction representa la tabla transactions (movimientos).
//
// Las cuentas de origen y destino admiten NULL según el tipo de movimiento,
// por eso son punteros: nil se guarda como NULL.
type Transaction struct {
	ID                   int64  `gorm:"column:id;primaryKey" json:"id"`
	SourceAccountID      *int64 `gorm:"column:source_account_id" json:"source_account_id"`
	DestinationAccountID *int64 `gorm:"column:destination_account_id" json:"destination_account_id"`
	Type                 string `gorm:"column:type" json:"type"`
	// NUMERIC(18,2): decimal exacto, siempre mayor que 0 (CHECK en SQL).
	Amount    decimal.Decimal `gorm:"column:amount" json:"amount"`
	CreatedAt time.Time       `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`

	// Relaciones
	SourceAccount      *Account `gorm:"foreignKey:SourceAccountID" json:"source_account,omitempty"`
	DestinationAccount *Account `gorm:"foreignKey:DestinationAccountID" json:"destination_account,omitempty"`
}

// TableName indica a GORM el nombre de la tabla.
func (Transaction) TableName() string { return "transactions" }
