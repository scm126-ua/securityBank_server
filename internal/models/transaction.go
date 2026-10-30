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
//
// Campos de seguridad añadidos en migración 000009:
//   - Reference: UUID único y público del movimiento (para trazabilidad).
//   - Description: texto libre opcional del motivo.
//   - IdempotencyKey: clave enviada por el cliente para evitar duplicados.
//   - IntegrityHMAC: HMAC-SHA256 del contenido del movimiento (anti-tampering).
type Transaction struct {
	ID                   int64           `gorm:"column:id;primaryKey" json:"-"`
	Reference            string          `gorm:"column:reference" json:"reference"`
	SourceAccountID      *int64          `gorm:"column:source_account_id" json:"source_account_id"`
	DestinationAccountID *int64          `gorm:"column:destination_account_id" json:"destination_account_id"`
	Type                 string          `gorm:"column:type" json:"type"`
	// NUMERIC(18,2): decimal exacto, siempre mayor que 0 (CHECK en SQL).
	Amount         decimal.Decimal `gorm:"column:amount" json:"amount"`
	Description    string          `gorm:"column:description" json:"description"`
	IdempotencyKey *string         `gorm:"column:idempotency_key" json:"-"`
	IntegrityHMAC  string          `gorm:"column:integrity_hmac" json:"-"`
	CreatedAt      time.Time       `gorm:"column:created_at;default:CURRENT_TIMESTAMP;autoCreateTime:false" json:"created_at"`

	// Relaciones (solo se rellenan si se cargan con Preload)
	SourceAccount      *Account `gorm:"foreignKey:SourceAccountID" json:"source_account,omitempty"`
	DestinationAccount *Account `gorm:"foreignKey:DestinationAccountID" json:"destination_account,omitempty"`
}

// TableName indica a GORM el nombre de la tabla.
func (Transaction) TableName() string { return "transactions" }
