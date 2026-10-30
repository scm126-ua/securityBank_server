package services

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/shopspring/decimal"

	"securityBank_server/internal/models"
)

func TestTransactionIntegrityAndReceipt(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generando clave de test: %v", err)
	}

	service := NewTransactionService(nil, nil, privateKey).(*transactionService)

	srcID := int64(10)
	dstID := int64(20)
	amount, _ := decimal.NewFromString("150.50")
	now := time.Now().UTC()
	ref := "f47ac10b-58cc-4372-a567-0e02b2c3d479"

	// 1. Probar cálculo y verificación de HMAC
	msg := fmt.Sprintf("%s|%s|%s|%d|%d|%d",
		ref, models.TransactionTypeTransfer, amount.StringFixed(2), srcID, dstID, now.UTC().Unix())
	mac := hmac.New(sha256.New, service.hmacKey)
	mac.Write([]byte(msg))
	hmacHex := hex.EncodeToString(mac.Sum(nil))

	tx := &models.Transaction{
		Reference:            ref,
		Type:                 models.TransactionTypeTransfer,
		Amount:               amount,
		SourceAccountID:      &srcID,
		DestinationAccountID: &dstID,
		IntegrityHMAC:        hmacHex,
		CreatedAt:            now,
	}

	if !service.VerifyIntegrity(tx) {
		t.Fatal("VerifyIntegrity falló para una transacción legítima")
	}

	// 2. Probar detección de manipulación (tampering con el importe)
	tamperedTx := *tx
	tamperedTx.Amount, _ = decimal.NewFromString("999999.00")
	if service.VerifyIntegrity(&tamperedTx) {
		t.Fatal("VerifyIntegrity no detectó la manipulación del importe")
	}

	// 3. Probar verificación de firma de Justificante (Receipt)
	receipt := TransactionReceipt{
		Version:              transactionReceiptVersion,
		ReceiptID:            "test-receipt-id",
		Reference:            ref,
		Type:                 models.TransactionTypeTransfer,
		Amount:               amount.String(),
		SourceAccountID:      &srcID,
		DestinationAccountID: &dstID,
		Description:          "Pago de prueba",
		CreatedAt:            now.Format(time.RFC3339),
		IssuedAt:             now.Format(time.RFC3339),
	}

	digest := sha256.Sum256(transactionReceiptPayload(receipt))
	sig, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("error firmando justificante de test: %v", err)
	}

	signed := &SignedTransactionReceipt{
		Receipt:            receipt,
		SignatureAlgorithm: "RSA-PSS-SHA256",
		Signature:          base64.StdEncoding.EncodeToString(sig),
	}

	if err := service.VerifyReceipt(signed); err != nil {
		t.Fatalf("VerifyReceipt falló para un justificante legítimo: %v", err)
	}

	// 4. Probar que la verificación falla si se altera el justificante
	tamperedReceipt := *signed
	tamperedReceipt.Receipt.Amount = "5000.00"
	if err := service.VerifyReceipt(&tamperedReceipt); err == nil {
		t.Fatal("VerifyReceipt debería fallar si los datos fueron alterados")
	}
}

func TestAccountStatementSigningAndVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generando clave de test: %v", err)
	}

	service := NewTransactionService(nil, nil, privateKey).(*transactionService)

	statement := AccountStatement{
		Version:           accountStatementVersion,
		StatementID:       "stmt-id-123456",
		AccountID:         42,
		IBAN:              "ES9121000418450200051332",
		HolderID:          1,
		HolderName:        "Test Holder",
		HolderDNI:         "12345678Z",
		CurrentBalance:    "1250.75",
		TotalDeposits:     "2000.00",
		TotalWithdrawals:  "500.00",
		TotalTransfersIn:  "0.00",
		TotalTransfersOut: "249.25",
		TransactionCount:  3,
		Transactions:      nil,
		IssuedAt:          time.Now().UTC().Format(time.RFC3339),
	}

	digest := sha256.Sum256(accountStatementPayload(statement))
	sig, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("error firmando extracto de test: %v", err)
	}

	signed := &SignedAccountStatement{
		Statement:          statement,
		SignatureAlgorithm: "RSA-PSS-SHA256",
		Signature:          base64.StdEncoding.EncodeToString(sig),
	}

	if err := service.VerifyStatement(signed); err != nil {
		t.Fatalf("VerifyStatement falló para un extracto legítimo: %v", err)
	}

	// Probar detección de manipulación en el extracto (por ejemplo alterar el saldo reflejado)
	tampered := *signed
	tampered.Statement.CurrentBalance = "999999.99"
	if err := service.VerifyStatement(&tampered); err == nil {
		t.Fatal("VerifyStatement debería fallar ante cualquier alteración del extracto")
	}
}
