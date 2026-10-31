package services

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/shopspring/decimal"

	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
)

const (
	transactionReceiptVersion = 1
	transactionReceiptContext = "securitybank-transaction-receipt-v1"

	accountStatementVersion = 1
	accountStatementContext = "securitybank-account-statement-v1"
)

var (
	ErrTransactionNotFound   = errors.New("transacción no encontrada")
	ErrDestinationNotFound   = errors.New("cuenta de destino no encontrada")
	ErrTamperedTransaction   = errors.New("la integridad del movimiento ha sido comprometida (HMAC no coincide)")
	ErrInvalidReceiptVersion = errors.New("versión de justificante no compatible")
	ErrInvalidReceiptSig     = errors.New("la firma del justificante no es válida")
	ErrInvalidStmtVersion    = errors.New("versión de extracto no compatible")
	ErrInvalidStmtSig        = errors.New("la firma del extracto no es válida")
)

// ─── Estructuras para justificante firmado ────────────────────────────────────

// TransactionReceipt contiene los datos auditables de un movimiento.
type TransactionReceipt struct {
	Version              int    `json:"version"`
	ReceiptID            string `json:"receipt_id"`
	Reference            string `json:"reference"`
	Type                 string `json:"type"`
	Amount               string `json:"amount"`
	SourceAccountID      *int64 `json:"source_account_id"`
	DestinationAccountID *int64 `json:"destination_account_id"`
	Description          string `json:"description"`
	CreatedAt            string `json:"created_at"`
	IssuedAt             string `json:"issued_at"`
}

// SignedTransactionReceipt encapsula el justificante junto a su firma RSA-PSS.
type SignedTransactionReceipt struct {
	Receipt            TransactionReceipt `json:"receipt"`
	SignatureAlgorithm string             `json:"signature_algorithm"`
	Signature          string             `json:"signature"`
}

// ─── Estructuras para extracto bancario oficial firmado ───────────────────────

// AccountStatement consolida el estado, saldos y movimientos de una cuenta.
type AccountStatement struct {
	Version           int                  `json:"version"`
	StatementID       string               `json:"statement_id"`
	AccountID         int64                `json:"account_id"`
	IBAN              string               `json:"iban"`
	HolderID          int64                `json:"holder_id"`
	HolderName        string               `json:"holder_name"`
	HolderDNI         string               `json:"holder_dni"`
	CurrentBalance    string               `json:"current_balance"`
	TotalDeposits     string               `json:"total_deposits"`
	TotalWithdrawals  string               `json:"total_withdrawals"`
	TotalTransfersIn  string               `json:"total_transfers_in"`
	TotalTransfersOut string               `json:"total_transfers_out"`
	TransactionCount  int                  `json:"transaction_count"`
	Transactions      []models.Transaction `json:"transactions"`
	IssuedAt          string               `json:"issued_at"`
}

// SignedAccountStatement encapsula el extracto bancario y su firma criptográfica RSA-PSS.
type SignedAccountStatement struct {
	Statement          AccountStatement `json:"statement"`
	SignatureAlgorithm string           `json:"signature_algorithm"`
	Signature          string           `json:"signature"`
}

// ─── Interfaz del Servicio ───────────────────────────────────────────────────

type TransactionService interface {
	Deposit(ctx context.Context, userID, accountID int64, amount decimal.Decimal, description, idempotencyKey string) (*models.Transaction, error)
	Withdraw(ctx context.Context, userID, accountID int64, amount decimal.Decimal, description, idempotencyKey string) (*models.Transaction, error)
	Transfer(ctx context.Context, userID, sourceAccountID int64, destIBAN string, amount decimal.Decimal, description, idempotencyKey string) (*models.Transaction, error)
	ListTransactions(ctx context.Context, userID, accountID int64, filter repositories.TransactionFilter, page, pageSize int) ([]models.Transaction, int64, error)
	VerifyIntegrity(tx *models.Transaction) bool
	GenerateReceipt(ctx context.Context, userID int64, reference string) (*SignedTransactionReceipt, error)
	VerifyReceipt(signedReceipt *SignedTransactionReceipt) error
	GenerateStatement(ctx context.Context, userID, accountID int64) (*SignedAccountStatement, error)
	VerifyStatement(signedStatement *SignedAccountStatement) error
}

type transactionService struct {
	txRepo           repositories.TransactionRepository
	accountRepo      *repositories.AccountRepository
	serverPrivateKey *rsa.PrivateKey
	hmacKey          []byte
	aesKey           []byte
}

// NewTransactionService crea una nueva instancia del servicio de transacciones.
func NewTransactionService(
	txRepo repositories.TransactionRepository,
	accountRepo *repositories.AccountRepository,
	serverPrivateKey *rsa.PrivateKey,
) TransactionService {
	h := sha256.New()
	h.Write([]byte("securitybank-transaction-hmac-v1-secret"))
	if serverPrivateKey != nil {
		h.Write(serverPrivateKey.D.Bytes())
	}
	derivedHMACKey := h.Sum(nil)

	hAES := sha256.New()
	hAES.Write([]byte("securitybank-db-field-encryption-v1"))
	if serverPrivateKey != nil {
		hAES.Write(serverPrivateKey.D.Bytes())
	}
	derivedAESKey := hAES.Sum(nil)

	return &transactionService{
		txRepo:           txRepo,
		accountRepo:      accountRepo,
		serverPrivateKey: serverPrivateKey,
		hmacKey:          derivedHMACKey,
		aesKey:           derivedAESKey,
	}
}

// encryptDescription cifra el concepto con AES-256-GCM y lo codifica en Base64 para guardarlo en BD.
func (s *transactionService) encryptDescription(plain string) string {
	if plain == "" {
		return ""
	}
	// Llama directamente a Encrypt de crypto_service.go
	ciphertext, err := Encrypt(s.aesKey, []byte(plain))
	if err != nil {
		return plain // fallback en caso de error
	}
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// decryptDescription descifra el texto de la BD con AES-256-GCM devolviendo el texto plano.
func (s *transactionService) decryptDescription(cipherText string) string {
	if cipherText == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return cipherText // si era texto plano anterior, lo devuelve tal cual
	}
	// Llama directamente a Decrypt de crypto_service.go
	plaintext, err := Decrypt(s.aesKey, data)
	if err != nil {
		return cipherText // si no era cifrado válido o falló el tag GCM
	}
	return string(plaintext)
}

// DeriveHMACKey exporta la función para inicializar el repositorio con la misma clave.
func DeriveHMACKey(serverPrivateKey *rsa.PrivateKey) []byte {
	h := sha256.New()
	h.Write([]byte("securitybank-transaction-hmac-v1-secret"))
	if serverPrivateKey != nil {
		h.Write(serverPrivateKey.D.Bytes())
	}
	return h.Sum(nil)
}

// ─── Operaciones Bancarias ───────────────────────────────────────────────────

func (s *transactionService) Deposit(
	ctx context.Context,
	userID, accountID int64,
	amount decimal.Decimal,
	description, idempotencyKey string,
) (*models.Transaction, error) {
	encDesc := s.encryptDescription(description)
	tx, err := s.txRepo.Deposit(ctx, userID, accountID, amount, encDesc, idempotencyKey)
	if err != nil {
		return nil, err
	}
	tx.Description = description // Devuelve el texto en claro a la vista del usuario
	return tx, nil
}
func (s *transactionService) Withdraw(
	ctx context.Context,
	userID, accountID int64,
	amount decimal.Decimal,
	description, idempotencyKey string,
) (*models.Transaction, error) {
	encDesc := s.encryptDescription(description)
	tx, err := s.txRepo.Withdraw(ctx, userID, accountID, amount, encDesc, idempotencyKey)
	if err != nil {
		return nil, err
	}
	tx.Description = description
	return tx, nil
}
func (s *transactionService) Transfer(
	ctx context.Context,
	userID, sourceAccountID int64,
	destIBAN string,
	amount decimal.Decimal,
	description, idempotencyKey string,
) (*models.Transaction, error) {
	destAccount, err := s.accountRepo.FindByIBAN(ctx, destIBAN)
	if err != nil {
		if errors.Is(err, repositories.ErrAccountNotFound) {
			return nil, ErrDestinationNotFound
		}
		return nil, fmt.Errorf("buscando cuenta destino: %w", err)
	}
	encDesc := s.encryptDescription(description)
	tx, err := s.txRepo.Transfer(ctx, userID, sourceAccountID, destAccount.ID, amount, encDesc, idempotencyKey)
	if err != nil {
		return nil, err
	}
	tx.Description = description
	return tx, nil
}

func (s *transactionService) ListTransactions(
	ctx context.Context,
	userID, accountID int64,
	filter repositories.TransactionFilter,
	page, pageSize int,
) ([]models.Transaction, int64, error) {
	txs, total, err := s.txRepo.ListForAccount(ctx, userID, accountID, filter, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	// Desciframos el concepto de cada movimiento antes de entregarlo a la interfaz
	for i := range txs {
		txs[i].Description = s.decryptDescription(txs[i].Description)
	}
	return txs, total, nil
}

// ─── Verificación de Integridad HMAC-SHA256 ──────────────────────────────────

func (s *transactionService) VerifyIntegrity(tx *models.Transaction) bool {
	if tx == nil || tx.IntegrityHMAC == "" {
		return false
	}

	src := "nil"
	if tx.SourceAccountID != nil {
		src = fmt.Sprintf("%d", *tx.SourceAccountID)
	}
	dst := "nil"
	if tx.DestinationAccountID != nil {
		dst = fmt.Sprintf("%d", *tx.DestinationAccountID)
	}

	msg := fmt.Sprintf("%s|%s|%s|%s|%s|%d",
		tx.Reference, tx.Type, tx.Amount.StringFixed(2), src, dst, tx.CreatedAt.UTC().Unix())

	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(msg))
	expectedHMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(tx.IntegrityHMAC), []byte(expectedHMAC))
}

// ─── Justificantes Verificables (RSA-PSS) ────────────────────────────────────

func (s *transactionService) GenerateReceipt(
	ctx context.Context,
	userID int64,
	reference string,
) (*SignedTransactionReceipt, error) {
	if s.serverPrivateKey == nil {
		return nil, errors.New("la clave privada del servidor no está disponible")
	}

	tx, err := s.txRepo.FindByReference(ctx, userID, reference)
	if err != nil {
		return nil, err
	}

	if !s.VerifyIntegrity(tx) {
		return nil, ErrTamperedTransaction
	}

	receiptDesc := s.decryptDescription(tx.Description)

	receiptIDBytes := make([]byte, 16)
	if _, err := rand.Read(receiptIDBytes); err != nil {
		return nil, fmt.Errorf("generando identificador del justificante: %w", err)
	}

	receipt := TransactionReceipt{
		Version:              transactionReceiptVersion,
		ReceiptID:            base64.RawURLEncoding.EncodeToString(receiptIDBytes),
		Reference:            tx.Reference,
		Type:                 tx.Type,
		Amount:               tx.Amount.String(),
		SourceAccountID:      tx.SourceAccountID,
		DestinationAccountID: tx.DestinationAccountID,
		Description:          receiptDesc,
		CreatedAt:            tx.CreatedAt.UTC().Format(time.RFC3339),
		IssuedAt:             time.Now().UTC().Format(time.RFC3339),
	}

	digest := sha256.Sum256(transactionReceiptPayload(receipt))
	signature, err := rsa.SignPSS(
		rand.Reader,
		s.serverPrivateKey,
		crypto.SHA256,
		digest[:],
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("firmando justificante: %w", err)
	}

	return &SignedTransactionReceipt{
		Receipt:            receipt,
		SignatureAlgorithm: "RSA-PSS-SHA256",
		Signature:          base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (s *transactionService) VerifyReceipt(signedReceipt *SignedTransactionReceipt) error {
	if s.serverPrivateKey == nil {
		return errors.New("clave pública no disponible")
	}
	if signedReceipt.Receipt.Version != transactionReceiptVersion ||
		signedReceipt.SignatureAlgorithm != "RSA-PSS-SHA256" {
		return ErrInvalidReceiptVersion
	}

	signature, err := base64.StdEncoding.Strict().DecodeString(signedReceipt.Signature)
	if err != nil {
		return errors.New("firma en formato incorrecto")
	}

	digest := sha256.Sum256(transactionReceiptPayload(signedReceipt.Receipt))
	if err := rsa.VerifyPSS(
		&s.serverPrivateKey.PublicKey,
		crypto.SHA256,
		digest[:],
		signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	); err != nil {
		return ErrInvalidReceiptSig
	}

	return nil
}

// ─── Extractos Bancarios Verificables (RSA-PSS) ───────────────────────────────

func (s *transactionService) GenerateStatement(
	ctx context.Context,
	userID, accountID int64,
) (*SignedAccountStatement, error) {
	if s.serverPrivateKey == nil {
		return nil, errors.New("la clave privada del servidor no está disponible")
	}

	// 1. RBAC y verificación de titularidad
	ownership, err := s.accountRepo.FindOwnership(ctx, userID, accountID)
	if err != nil {
		return nil, err
	}

	account, err := s.accountRepo.FindByIBAN(ctx, string(ownership.IBAN))
	if err != nil {
		return nil, err
	}

	// 2. Obtener movimientos (hasta 100 movimientos más recientes para el extracto)
	txs, _, err := s.txRepo.ListForAccount(ctx, userID, accountID, repositories.TransactionFilter{}, 1, 100)
	if err != nil {
		return nil, fmt.Errorf("obteniendo movimientos del extracto: %w", err)
	}

	// 3. Calcular totales acumulados
	var totalDeposits, totalWithdrawals, totalTransfersIn, totalTransfersOut decimal.Decimal
	for _, t := range txs {
		switch t.Type {
		case models.TransactionTypeDeposit:
			totalDeposits = totalDeposits.Add(t.Amount)
		case models.TransactionTypeWithdrawal:
			totalWithdrawals = totalWithdrawals.Add(t.Amount)
		case models.TransactionTypeTransfer:
			if t.DestinationAccountID != nil && *t.DestinationAccountID == accountID {
				totalTransfersIn = totalTransfersIn.Add(t.Amount)
			} else {
				totalTransfersOut = totalTransfersOut.Add(t.Amount)
			}
		}
	}

	statementIDBytes := make([]byte, 16)
	if _, err := rand.Read(statementIDBytes); err != nil {
		return nil, fmt.Errorf("generando identificador del extracto: %w", err)
	}

	now := time.Now().UTC()
	statement := AccountStatement{
		Version:           accountStatementVersion,
		StatementID:       base64.RawURLEncoding.EncodeToString(statementIDBytes),
		AccountID:         accountID,
		IBAN:              string(account.IBAN),
		HolderID:          ownership.HolderID,
		HolderName:        ownership.HolderName,
		HolderDNI:         string(ownership.HolderDNI),
		CurrentBalance:    account.Balance.String(),
		TotalDeposits:     totalDeposits.String(),
		TotalWithdrawals:  totalWithdrawals.String(),
		TotalTransfersIn:  totalTransfersIn.String(),
		TotalTransfersOut: totalTransfersOut.String(),
		TransactionCount:  len(txs),
		Transactions:      txs,
		IssuedAt:          now.Format(time.RFC3339),
	}

	digest := sha256.Sum256(accountStatementPayload(statement))
	signature, err := rsa.SignPSS(
		rand.Reader,
		s.serverPrivateKey,
		crypto.SHA256,
		digest[:],
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("firmando extracto bancario: %w", err)
	}

	return &SignedAccountStatement{
		Statement:          statement,
		SignatureAlgorithm: "RSA-PSS-SHA256",
		Signature:          base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (s *transactionService) VerifyStatement(signedStatement *SignedAccountStatement) error {
	if s.serverPrivateKey == nil {
		return errors.New("clave pública no disponible")
	}
	if signedStatement.Statement.Version != accountStatementVersion ||
		signedStatement.SignatureAlgorithm != "RSA-PSS-SHA256" {
		return ErrInvalidStmtVersion
	}

	signature, err := base64.StdEncoding.Strict().DecodeString(signedStatement.Signature)
	if err != nil {
		return errors.New("firma en formato incorrecto")
	}

	digest := sha256.Sum256(accountStatementPayload(signedStatement.Statement))
	if err := rsa.VerifyPSS(
		&s.serverPrivateKey.PublicKey,
		crypto.SHA256,
		digest[:],
		signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	); err != nil {
		return ErrInvalidStmtSig
	}

	return nil
}

// ─── Payloads canónicos prefijados por longitud ──────────────────────────────

func transactionReceiptPayload(receipt TransactionReceipt) []byte {
	src := "nil"
	if receipt.SourceAccountID != nil {
		src = strconv.FormatInt(*receipt.SourceAccountID, 10)
	}
	dst := "nil"
	if receipt.DestinationAccountID != nil {
		dst = strconv.FormatInt(*receipt.DestinationAccountID, 10)
	}

	fields := []string{
		transactionReceiptContext,
		strconv.Itoa(receipt.Version),
		receipt.ReceiptID,
		receipt.Reference,
		receipt.Type,
		receipt.Amount,
		src,
		dst,
		receipt.Description,
		receipt.CreatedAt,
		receipt.IssuedAt,
	}

	return encodeCanonicalFields(fields)
}

func accountStatementPayload(stmt AccountStatement) []byte {
	fields := []string{
		accountStatementContext,
		strconv.Itoa(stmt.Version),
		stmt.StatementID,
		strconv.FormatInt(stmt.AccountID, 10),
		stmt.IBAN,
		strconv.FormatInt(stmt.HolderID, 10),
		stmt.HolderName,
		stmt.HolderDNI,
		stmt.CurrentBalance,
		stmt.TotalDeposits,
		stmt.TotalWithdrawals,
		stmt.TotalTransfersIn,
		stmt.TotalTransfersOut,
		strconv.Itoa(stmt.TransactionCount),
		stmt.IssuedAt,
	}

	return encodeCanonicalFields(fields)
}

func encodeCanonicalFields(fields []string) []byte {
	payload := make([]byte, 0)
	for _, field := range fields {
		encodedLength := make([]byte, 4)
		binary.BigEndian.PutUint32(encodedLength, uint32(len(field)))
		payload = append(payload, encodedLength...)
		payload = append(payload, field...)
	}
	return payload
}
