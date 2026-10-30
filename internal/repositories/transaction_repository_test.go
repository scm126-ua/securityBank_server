package repositories

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/shopspring/decimal"

	"securityBank_server/internal/database"
	"securityBank_server/internal/models"
)

// TestTransactionDepositAndWithdraw prueba el flujo básico de ingreso y retirada con control de saldo.
func TestTransactionDepositAndWithdraw(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no está disponible")
	}

	db, err := database.Connect(databaseURL)
	if err != nil {
		t.Fatalf("conectando a BD: %v", err)
	}

	tx := db.Begin()
	defer tx.Rollback()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())[:15]
	user := createSecurityTestUser(t, tx, "txuser", suffix)
	acc, err := createAccount(tx, user.ID, "ES99"+suffix)
	if err != nil {
		t.Fatalf("creando cuenta: %v", err)
	}

	repo := NewTransactionRepository(tx, []byte("test-hmac-key-32bytes-long-secret!"))

	// 1. Ingresar 500.00
	depositAmt, _ := decimal.NewFromString("500.00")
	depositTx, err := repo.Deposit(context.Background(), user.ID, acc.ID, depositAmt, "Nómina", "idemp-dep-1")
	if err != nil {
		t.Fatalf("error en depósito: %v", err)
	}
	if depositTx.Amount.Cmp(depositAmt) != 0 {
		t.Fatalf("importe inesperado: %s", depositTx.Amount.String())
	}

	// 2. Comprobar clave de idempotencia duplicada (Doble gasto / repetición)
	_, err = repo.Deposit(context.Background(), user.ID, acc.ID, depositAmt, "Nómina repetida", "idemp-dep-1")
	if !errors.Is(err, ErrDuplicateOperation) {
		t.Fatalf("se esperaba ErrDuplicateOperation, recibido: %v", err)
	}

	// 3. Retirar 200.00
	withdrawAmt, _ := decimal.NewFromString("200.00")
	_, err = repo.Withdraw(context.Background(), user.ID, acc.ID, withdrawAmt, "Cajero", "idemp-wth-1")
	if err != nil {
		t.Fatalf("error en retirada: %v", err)
	}

	// Saldo debe ser 300.00
	var checkAcc models.Account
	tx.First(&checkAcc, acc.ID)
	expectedBalance, _ := decimal.NewFromString("300.00")
	if checkAcc.Balance.Cmp(expectedBalance) != 0 {
		t.Fatalf("saldo esperado %s, obtenido %s", expectedBalance, checkAcc.Balance)
	}

	// 4. Intentar retirar 400.00 (debe fallar por saldo insuficiente)
	tooMuch, _ := decimal.NewFromString("400.00")
	_, err = repo.Withdraw(context.Background(), user.ID, acc.ID, tooMuch, "Exceso", "idemp-wth-2")
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("se esperaba ErrInsufficientBalance, recibido: %v", err)
	}

	// El saldo debe seguir intacto en 300.00
	tx.First(&checkAcc, acc.ID)
	if checkAcc.Balance.Cmp(expectedBalance) != 0 {
		t.Fatalf("el saldo no debe modificarse si la retirada fue rechazada")
	}
}

// TestTransactionTransferAndRollback verifica que si una transferencia falla
// a mitad de camino, se revierte atómicamente (Rollback ACID) y el saldo no se altera.
func TestTransactionTransferAndRollback(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no está disponible")
	}

	db, err := database.Connect(databaseURL)
	if err != nil {
		t.Fatalf("conectando a BD: %v", err)
	}

	tx := db.Begin()
	defer tx.Rollback()

	nowNanos := time.Now().UnixNano()
	suffixA := fmt.Sprintf("%d", nowNanos)[:14] + "1"
	suffixB := fmt.Sprintf("%d", nowNanos)[:14] + "2"
	userA := createSecurityTestUser(t, tx, "alice", suffixA)
	userB := createSecurityTestUser(t, tx, "bob", suffixB)

	accA, err := createAccount(tx, userA.ID, "ESA"+suffixA)
	if err != nil {
		t.Fatalf("creando cuenta A: %v", err)
	}
	accB, err := createAccount(tx, userB.ID, "ESB"+suffixB)
	if err != nil {
		t.Fatalf("creando cuenta B: %v", err)
	}

	repo := NewTransactionRepository(tx, []byte("test-hmac-key-32bytes-long-secret!"))

	// Ingresar 100 en cuenta A
	initAmt, _ := decimal.NewFromString("100.00")
	_, err = repo.Deposit(context.Background(), userA.ID, accA.ID, initAmt, "Fondo inicial", "")
	if err != nil {
		t.Fatalf("depósito inicial: %v", err)
	}

	// Cerrar la cuenta B para forzar un error durante la transferencia
	tx.Model(&models.Account{}).Where("id = ?", accB.ID).Update("status", models.AccountStatusClosed)

	// Intentar transferir de A a B (cerrada)
	transferAmt, _ := decimal.NewFromString("50.00")
	_, err = repo.Transfer(context.Background(), userA.ID, accA.ID, accB.ID, transferAmt, "A cerrada", "")
	if !errors.Is(err, ErrAccountClosed) {
		t.Fatalf("se esperaba ErrAccountClosed, recibido: %v", err)
	}

	// Comprobar Rollback automático: el saldo de A debe mantenerse intacto en 100.00
	var storedA models.Account
	tx.First(&storedA, accA.ID)
	if storedA.Balance.Cmp(initAmt) != 0 {
		t.Fatalf("Rollback falló: el saldo de A cambió a %s (se esperaba %s)", storedA.Balance, initAmt)
	}
}

// TestConcurrentWithdrawals verifica la prevención de Race Conditions.
// Se lanzan múltiples retiradas concurrentes sobre una cuenta con saldo limitado;
// gracias al SELECT FOR UPDATE, nunca se produce sobregiro ni saldo negativo.
func TestConcurrentWithdrawals(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no está disponible")
	}

	db, err := database.Connect(databaseURL)
	if err != nil {
		t.Fatalf("conectando a BD: %v", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())[:15]
	user := createSecurityTestUser(t, db, "conc", suffix)
	acc, err := createAccount(db, user.ID, "ESC"+suffix)
	if err != nil {
		t.Fatalf("creando cuenta: %v", err)
	}

	repo := NewTransactionRepository(db, []byte("test-hmac-key-32bytes-long-secret!"))

	// Saldo inicial: 100.00
	initialAmount, _ := decimal.NewFromString("100.00")
	_, err = repo.Deposit(context.Background(), user.ID, acc.ID, initialAmount, "Saldo prueba concurrencia", "")
	if err != nil {
		t.Fatalf("ingreso inicial: %v", err)
	}

	// Lanzamos 10 goroutines concurrentes intentando retirar 20.00 cada una (Total = 200.00 solicitado).
	// Como el saldo es 100.00, exactamente 5 deben tener éxito y 5 deben fallar con ErrInsufficientBalance.
	// El saldo final debe ser exactamente 0.00, NUNCA negativo.
	concurrentCount := 10
	withdrawAmount, _ := decimal.NewFromString("20.00")

	var wg sync.WaitGroup
	var successCount int64
	var failureCount int64
	var mu sync.Mutex

	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := repo.Withdraw(context.Background(), user.ID, acc.ID, withdrawAmount, fmt.Sprintf("Retirada conc %d", index), "")
			mu.Lock()
			if err == nil {
				successCount++
			} else if errors.Is(err, ErrInsufficientBalance) {
				failureCount++
			}
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	if successCount != 5 {
		t.Fatalf("deberían haber tenido éxito exactamente 5 operaciones, tuvieron: %d", successCount)
	}
	if failureCount != 5 {
		t.Fatalf("deberían haber fallado exactamente 5 operaciones por saldo insuficiente, fallaron: %d", failureCount)
	}

	var finalAcc models.Account
	if err := db.First(&finalAcc, acc.ID).Error; err != nil {
		t.Fatalf("recuperando cuenta final: %v", err)
	}

	zero := decimal.Zero
	if finalAcc.Balance.Cmp(zero) != 0 {
		t.Fatalf("el saldo final debe ser 0.00, pero es: %s", finalAcc.Balance)
	}
}
