package repositories

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/shopspring/decimal"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"securityBank_server/internal/models"
)

// ─── Errores de dominio ──────────────────────────────────────────────────────

// ErrInsufficientBalance se devuelve cuando el saldo disponible es menor que
// el importe solicitado en una retirada o transferencia.
var ErrInsufficientBalance = errors.New("saldo insuficiente")

// ErrAccountClosed se devuelve cuando se intenta operar sobre una cuenta cerrada.
var ErrAccountClosed = errors.New("cuenta cerrada")

// ErrUnauthorized se devuelve cuando el usuario no es titular de la cuenta.
var ErrUnauthorized = errors.New("acceso no autorizado a la cuenta")

// ErrSameAccount se devuelve en transferencias cuando origen y destino coinciden.
var ErrSameAccount = errors.New("origen y destino deben ser cuentas distintas")

// ErrInvalidAmount se devuelve si el importe es <= 0.
var ErrInvalidAmount = errors.New("el importe debe ser mayor que cero")

// ErrDuplicateOperation se devuelve cuando ya existe una transacción con la
// misma clave de idempotencia.
var ErrDuplicateOperation = errors.New("operación duplicada: ya existe una transacción con esa clave")

// ─── Filtros de listado ───────────────────────────────────────────────────────

// TransactionFilter permite filtrar el historial por tipo de movimiento.
type TransactionFilter struct {
	Type string // "DEPOSIT" | "WITHDRAWAL" | "TRANSFER" | "" (todos)
}

// ─── Interfaz pública ─────────────────────────────────────────────────────────

// TransactionRepository define las operaciones disponibles sobre transacciones.
// Todas las operaciones que modifican saldo son atómicas (transacción ACID).
type TransactionRepository interface {
	// Deposit ingresa Amount en la cuenta AccountID del usuario UserID.
	Deposit(ctx context.Context, userID, accountID int64, amount decimal.Decimal, description, idempotencyKey string) (*models.Transaction, error)

	// Withdraw retira Amount de la cuenta AccountID del usuario UserID.
	Withdraw(ctx context.Context, userID, accountID int64, amount decimal.Decimal, description, idempotencyKey string) (*models.Transaction, error)

	// Transfer mueve Amount desde SourceAccountID hacia DestAccountID.
	// SourceAccountID debe pertenecer a UserID; DestAccountID puede ser de otro usuario.
	Transfer(ctx context.Context, userID, sourceAccountID, destAccountID int64, amount decimal.Decimal, description, idempotencyKey string) (*models.Transaction, error)

	// ListForAccount devuelve los movimientos de la cuenta AccountID de forma
	// paginada y filtrada. Verifica que UserID sea titular de la cuenta.
	ListForAccount(ctx context.Context, userID, accountID int64, filter TransactionFilter, page, pageSize int) ([]models.Transaction, int64, error)

	// FindByReference devuelve una transacción por su UUID de referencia.
	// Verifica que UserID sea titular de alguna de las cuentas implicadas.
	FindByReference(ctx context.Context, userID int64, reference string) (*models.Transaction, error)
}

// ─── Implementación ───────────────────────────────────────────────────────────

type transactionRepository struct {
	db      *gorm.DB
	hmacKey []byte // clave secreta para HMAC-SHA256 de integridad
}

// NewTransactionRepository crea el repositorio. hmacKey es una clave secreta
// del servidor (mínimo 32 bytes recomendados) que se usa para calcular el HMAC
// de integridad de cada transacción.
func NewTransactionRepository(db *gorm.DB, hmacKey []byte) TransactionRepository {
	return &transactionRepository{db: db, hmacKey: hmacKey}
}

// ─── Deposit ─────────────────────────────────────────────────────────────────

func (r *transactionRepository) Deposit(
	ctx context.Context,
	userID, accountID int64,
	amount decimal.Decimal,
	description, idempotencyKey string,
) (*models.Transaction, error) {
	if amount.LessThanOrEqual(decimal.Zero) {
		return nil, ErrInvalidAmount
	}

	var result *models.Transaction
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 1. Bloquear la cuenta en exclusiva (SELECT FOR UPDATE) para evitar
		//    race conditions. Nadie más puede leer ni escribir esta fila hasta
		//    que se haga COMMIT o ROLLBACK.
		account, err := lockAccount(tx, accountID)
		if err != nil {
			r.insertAuditDenied(tx, userID, &accountID, nil, models.TransactionAuditActionDeposit, reasonFromErr(err))
			return err
		}

		// 2. RBAC: verificar que el usuario sea titular de la cuenta.
		if err := assertOwner(tx, userID, accountID); err != nil {
			r.insertAuditDenied(tx, userID, &accountID, nil, models.TransactionAuditActionDeposit, models.TransactionAuditReasonUnauthorized)
			return err
		}

		// 3. Comprobar idempotencia (evitar operaciones duplicadas).
		if idempotencyKey != "" {
			if dup, err := r.checkIdempotency(tx, idempotencyKey); err != nil {
				return err
			} else if dup {
				r.insertAuditDenied(tx, userID, &accountID, nil, models.TransactionAuditActionDeposit, models.TransactionAuditReasonDuplicateOperation)
				return ErrDuplicateOperation
			}
		}

		// 4. Actualizar el saldo sumando el importe (NUMERIC exacto).
		newBalance := account.Balance.Add(amount)
		if err := tx.Model(&models.Account{}).Where("id = ?", accountID).
			Update("balance", newBalance).Error; err != nil {
			return fmt.Errorf("actualizando saldo: %w", err)
		}

		// 5. Crear el registro de transacción con su referencia UUID y HMAC.
		ref, err := generateUUIDv4()
		if err != nil {
			return fmt.Errorf("generando referencia uuid: %w", err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		ik := nullableString(idempotencyKey)
		txRecord := models.Transaction{
			Reference:            ref,
			SourceAccountID:      nil,
			DestinationAccountID: &accountID,
			Type:                 models.TransactionTypeDeposit,
			Amount:               amount,
			Description:          description,
			IdempotencyKey:       ik,
			IntegrityHMAC:        r.computeHMAC(ref, models.TransactionTypeDeposit, amount, nil, &accountID, now),
			CreatedAt:            now,
		}
		if err := tx.Create(&txRecord).Error; err != nil {
			return fmt.Errorf("creando transacción: %w", err)
		}

		// 6. Insertar evento de auditoría de éxito (en la misma transacción BD).
		r.insertAuditSuccess(tx, userID, &accountID, ref, models.TransactionAuditActionDeposit)

		result = &txRecord
		return nil
	})

	return result, err
}

// ─── Withdraw ────────────────────────────────────────────────────────────────

func (r *transactionRepository) Withdraw(
	ctx context.Context,
	userID, accountID int64,
	amount decimal.Decimal,
	description, idempotencyKey string,
) (*models.Transaction, error) {
	if amount.LessThanOrEqual(decimal.Zero) {
		return nil, ErrInvalidAmount
	}

	var result *models.Transaction
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		account, err := lockAccount(tx, accountID)
		if err != nil {
			r.insertAuditDenied(tx, userID, &accountID, nil, models.TransactionAuditActionWithdrawal, reasonFromErr(err))
			return err
		}

		if err := assertOwner(tx, userID, accountID); err != nil {
			r.insertAuditDenied(tx, userID, &accountID, nil, models.TransactionAuditActionWithdrawal, models.TransactionAuditReasonUnauthorized)
			return err
		}

		if idempotencyKey != "" {
			if dup, err := r.checkIdempotency(tx, idempotencyKey); err != nil {
				return err
			} else if dup {
				r.insertAuditDenied(tx, userID, &accountID, nil, models.TransactionAuditActionWithdrawal, models.TransactionAuditReasonDuplicateOperation)
				return ErrDuplicateOperation
			}
		}

		// Control de saldo y doble gasto: rechazar si el saldo es insuficiente.
		if account.Balance.LessThan(amount) {
			r.insertAuditDenied(tx, userID, &accountID, nil, models.TransactionAuditActionWithdrawal, models.TransactionAuditReasonInsufficientBalance)
			return ErrInsufficientBalance
		}

		newBalance := account.Balance.Sub(amount)
		if err := tx.Model(&models.Account{}).Where("id = ?", accountID).
			Update("balance", newBalance).Error; err != nil {
			return fmt.Errorf("actualizando saldo: %w", err)
		}

		ref, err := generateUUIDv4()
		if err != nil {
			return fmt.Errorf("generando referencia uuid: %w", err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		ik := nullableString(idempotencyKey)
		txRecord := models.Transaction{
			Reference:            ref,
			SourceAccountID:      &accountID,
			DestinationAccountID: nil,
			Type:                 models.TransactionTypeWithdrawal,
			Amount:               amount,
			Description:          description,
			IdempotencyKey:       ik,
			IntegrityHMAC:        r.computeHMAC(ref, models.TransactionTypeWithdrawal, amount, &accountID, nil, now),
			CreatedAt:            now,
		}
		if err := tx.Create(&txRecord).Error; err != nil {
			return fmt.Errorf("creando transacción: %w", err)
		}

		r.insertAuditSuccess(tx, userID, &accountID, ref, models.TransactionAuditActionWithdrawal)
		result = &txRecord
		return nil
	})

	return result, err
}

// ─── Transfer ────────────────────────────────────────────────────────────────

func (r *transactionRepository) Transfer(
	ctx context.Context,
	userID, sourceAccountID, destAccountID int64,
	amount decimal.Decimal,
	description, idempotencyKey string,
) (*models.Transaction, error) {
	if amount.LessThanOrEqual(decimal.Zero) {
		return nil, ErrInvalidAmount
	}
	if sourceAccountID == destAccountID {
		return nil, ErrSameAccount
	}

	var result *models.Transaction
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Prevención de deadlock: siempre bloqueamos primero la cuenta con
		// menor ID. Así dos transferencias cruzadas no se bloquean mutuamente.
		firstID, secondID := sourceAccountID, destAccountID
		if destAccountID < sourceAccountID {
			firstID, secondID = destAccountID, sourceAccountID
		}

		if _, err := lockAccount(tx, firstID); err != nil {
			r.insertAuditDenied(tx, userID, &sourceAccountID, nil, models.TransactionAuditActionTransfer, reasonFromErr(err))
			return err
		}
		if _, err := lockAccount(tx, secondID); err != nil {
			r.insertAuditDenied(tx, userID, &sourceAccountID, nil, models.TransactionAuditActionTransfer, reasonFromErr(err))
			return err
		}

		// Ahora cargamos ambas cuentas ya con los datos actualizados.
		var src, dst models.Account
		if err := tx.First(&src, sourceAccountID).Error; err != nil {
			return ErrAccountNotFound
		}
		if err := tx.First(&dst, destAccountID).Error; err != nil {
			return ErrAccountNotFound
		}

		// RBAC: la cuenta origen debe pertenecer al usuario.
		if err := assertOwner(tx, userID, sourceAccountID); err != nil {
			r.insertAuditDenied(tx, userID, &sourceAccountID, nil, models.TransactionAuditActionTransfer, models.TransactionAuditReasonUnauthorized)
			return err
		}

		if src.Status != "ACTIVE" {
			r.insertAuditDenied(tx, userID, &sourceAccountID, nil, models.TransactionAuditActionTransfer, models.TransactionAuditReasonAccountClosed)
			return ErrAccountClosed
		}
		if dst.Status != "ACTIVE" {
			r.insertAuditDenied(tx, userID, &sourceAccountID, nil, models.TransactionAuditActionTransfer, models.TransactionAuditReasonAccountClosed)
			return ErrAccountClosed
		}

		if idempotencyKey != "" {
			if dup, err := r.checkIdempotency(tx, idempotencyKey); err != nil {
				return err
			} else if dup {
				r.insertAuditDenied(tx, userID, &sourceAccountID, nil, models.TransactionAuditActionTransfer, models.TransactionAuditReasonDuplicateOperation)
				return ErrDuplicateOperation
			}
		}

		// Control de saldo: el origen debe tener suficiente.
		if src.Balance.LessThan(amount) {
			r.insertAuditDenied(tx, userID, &sourceAccountID, nil, models.TransactionAuditActionTransfer, models.TransactionAuditReasonInsufficientBalance)
			return ErrInsufficientBalance
		}

		// Actualizar ambos saldos en la misma transacción BD.
		if err := tx.Model(&models.Account{}).Where("id = ?", sourceAccountID).
			Update("balance", src.Balance.Sub(amount)).Error; err != nil {
			return fmt.Errorf("actualizando saldo origen: %w", err)
		}
		if err := tx.Model(&models.Account{}).Where("id = ?", destAccountID).
			Update("balance", dst.Balance.Add(amount)).Error; err != nil {
			return fmt.Errorf("actualizando saldo destino: %w", err)
		}

		ref, err := generateUUIDv4()
		if err != nil {
			return fmt.Errorf("generando referencia uuid: %w", err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		ik := nullableString(idempotencyKey)
		txRecord := models.Transaction{
			Reference:            ref,
			SourceAccountID:      &sourceAccountID,
			DestinationAccountID: &destAccountID,
			Type:                 models.TransactionTypeTransfer,
			Amount:               amount,
			Description:          description,
			IdempotencyKey:       ik,
			IntegrityHMAC:        r.computeHMAC(ref, models.TransactionTypeTransfer, amount, &sourceAccountID, &destAccountID, now),
			CreatedAt:            now,
		}
		if err := tx.Create(&txRecord).Error; err != nil {
			return fmt.Errorf("creando transacción: %w", err)
		}

		r.insertAuditSuccess(tx, userID, &sourceAccountID, ref, models.TransactionAuditActionTransfer)
		result = &txRecord
		return nil
	})

	return result, err
}

// ─── ListForAccount ───────────────────────────────────────────────────────────

func (r *transactionRepository) ListForAccount(
	ctx context.Context,
	userID, accountID int64,
	filter TransactionFilter,
	page, pageSize int,
) ([]models.Transaction, int64, error) {
	// Verificar titularidad antes de devolver datos.
	if err := assertOwner(r.db.WithContext(ctx), userID, accountID); err != nil {
		return nil, 0, err
	}

	// La cuenta debe existir.
	var acc models.Account
	if err := r.db.WithContext(ctx).First(&acc, accountID).Error; err != nil {
		return nil, 0, ErrAccountNotFound
	}

	// Construir la query base: movimientos donde la cuenta es origen O destino.
	base := r.db.WithContext(ctx).Model(&models.Transaction{}).
		Where("source_account_id = ? OR destination_account_id = ?", accountID, accountID)

	if filter.Type != "" {
		base = base.Where("type = ?", filter.Type)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("contando transacciones: %w", err)
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var txs []models.Transaction
	if err := base.Order("created_at DESC").
		Limit(pageSize).Offset(offset).
		Find(&txs).Error; err != nil {
		return nil, 0, fmt.Errorf("listando transacciones: %w", err)
	}

	return txs, total, nil
}

// ─── FindByReference ──────────────────────────────────────────────────────────

func (r *transactionRepository) FindByReference(
	ctx context.Context,
	userID int64,
	reference string,
) (*models.Transaction, error) {
	var tx models.Transaction
	if err := r.db.WithContext(ctx).
		Where("reference = ?", reference).
		First(&tx).Error; err != nil {
		return nil, ErrAccountNotFound
	}

	// El usuario debe ser titular de alguna cuenta implicada en el movimiento.
	authorized := false
	if tx.SourceAccountID != nil {
		if err := assertOwner(r.db.WithContext(ctx), userID, *tx.SourceAccountID); err == nil {
			authorized = true
		}
	}
	if !authorized && tx.DestinationAccountID != nil {
		if err := assertOwner(r.db.WithContext(ctx), userID, *tx.DestinationAccountID); err == nil {
			authorized = true
		}
	}
	if !authorized {
		return nil, ErrUnauthorized
	}

	return &tx, nil
}

// ─── Helpers internos ─────────────────────────────────────────────────────────

// generateUUIDv4 genera un UUID versión 4 RFC 4122 criptográficamente seguro
// usando crypto/rand, sin necesidad de dependencias externas.
func generateUUIDv4() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // versión 4
	b[8] = (b[8] & 0x3f) | 0x80 // variante RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// lockAccount obtiene un SELECT FOR UPDATE sobre la cuenta para garantizar
// exclusión mutua mientras se opera. Devuelve ErrAccountNotFound si no existe
// y ErrAccountClosed si está cerrada.
func lockAccount(tx *gorm.DB, accountID int64) (*models.Account, error) {
	var acc models.Account
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&acc, accountID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("bloqueando cuenta: %w", err)
	}
	if acc.Status != "ACTIVE" {
		return nil, ErrAccountClosed
	}
	return &acc, nil
}

// assertOwner verifica que userID sea titular de accountID consultando la
// tabla account_users. Devuelve ErrUnauthorized si no lo es.
func assertOwner(db *gorm.DB, userID, accountID int64) error {
	var count int64
	db.Model(&models.AccountUser{}).
		Where("user_id = ? AND account_id = ?", userID, accountID).
		Count(&count)
	if count == 0 {
		return ErrUnauthorized
	}
	return nil
}

// checkIdempotency devuelve true si ya existe una transacción con esa clave.
func (r *transactionRepository) checkIdempotency(tx *gorm.DB, key string) (bool, error) {
	var count int64
	if err := tx.Model(&models.Transaction{}).
		Where("idempotency_key = ?", key).
		Count(&count).Error; err != nil {
		return false, fmt.Errorf("comprobando idempotencia: %w", err)
	}
	return count > 0, nil
}

// computeHMAC calcula HMAC-SHA256 del contenido de una transacción para
// detectar modificaciones posteriores en la base de datos (integridad).
func (r *transactionRepository) computeHMAC(
	reference, txType string,
	amount decimal.Decimal,
	srcID, dstID *int64,
	createdAt time.Time,
) string {
	src := "nil"
	if srcID != nil {
		src = fmt.Sprintf("%d", *srcID)
	}
	dst := "nil"
	if dstID != nil {
		dst = fmt.Sprintf("%d", *dstID)
	}
	msg := fmt.Sprintf("%s|%s|%s|%s|%s|%d",
		reference, txType, amount.StringFixed(2), src, dst, createdAt.UTC().Unix())

	mac := hmac.New(sha256.New, r.hmacKey)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// insertAuditSuccess inserta un evento de auditoría exitoso dentro de la
// transacción BD activa.
func (r *transactionRepository) insertAuditSuccess(
	tx *gorm.DB, userID int64, accountID *int64, ref, action string,
) {
	event := models.TransactionAuditEvent{
		UserID:               userID,
		AccountID:            accountID,
		TransactionReference: &ref,
		Action:               action,
		Result:               models.TransactionAuditResultSuccess,
	}
	tx.Create(&event)
}

// insertAuditDenied inserta un evento de auditoría de operación rechazada.
func (r *transactionRepository) insertAuditDenied(
	tx *gorm.DB, userID int64, accountID *int64, ref *string, action, reason string,
) {
	event := models.TransactionAuditEvent{
		UserID:               userID,
		AccountID:            accountID,
		TransactionReference: ref,
		Action:               action,
		Result:               models.TransactionAuditResultDenied,
		Reason:               &reason,
	}
	tx.Create(&event)
}

// reasonFromErr convierte un error de dominio en una constante de razón de rechazo.
func reasonFromErr(err error) string {
	switch {
	case errors.Is(err, ErrAccountNotFound):
		return models.TransactionAuditReasonAccountNotFound
	case errors.Is(err, ErrAccountClosed):
		return models.TransactionAuditReasonAccountClosed
	case errors.Is(err, ErrUnauthorized):
		return models.TransactionAuditReasonUnauthorized
	case errors.Is(err, ErrInsufficientBalance):
		return models.TransactionAuditReasonInsufficientBalance
	default:
		return models.TransactionAuditReasonInvalidAmount
	}
}

// nullableString devuelve nil si s es vacío, o un puntero a s si no lo es.
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
