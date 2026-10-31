package repositories

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/gorm"

	"securityBank_server/internal/database"
	"securityBank_server/internal/models"
)

// La clave de datos sensibles se configura una sola vez para las pruebas del
// paquete. Si DATA_ENCRYPTION_KEY está definida (por ejemplo, al ejecutar los
// tests dentro del backend), se usa la misma que la aplicación para que los
// datos que dejan algunos tests de integración sigan siendo legibles.
func TestMain(m *testing.M) {
	key := []byte("01234567890123456789012345678901")
	if encoded := os.Getenv("DATA_ENCRYPTION_KEY"); encoded != "" {
		if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(decoded) == 32 {
			key = decoded
		}
	}

	if err := models.SetDataEncryptionKey(key); err != nil {
		fmt.Fprintf(os.Stderr, "no se pudo configurar la clave de pruebas: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// Comprueba que el DNI y el IBAN se guardan cifrados y que la búsqueda por
// blind index sigue funcionando sin descifrar las columnas.
func TestSensitiveValuesAreEncryptedAtRest(t *testing.T) {
	db := connectIntegrationDB(t)
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("no se pudo iniciar la transacción de prueba: %v", tx.Error)
	}
	defer rollback(t, tx)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	dni := "12345678Z"
	iban := fmt.Sprintf("ES91%020d", time.Now().UnixNano())

	user := &models.User{
		Name:         "cifrado at rest",
		DNI:          models.EncryptedString(dni),
		Email:        "cifrado-" + suffix + "@securitybank.test",
		PasswordHash: "test-password-hash",
		Salt:         "test-salt",
		Role:         models.UserRoleClient,
	}
	if err := tx.Create(user).Error; err != nil {
		t.Fatalf("no se pudo crear el usuario de prueba: %v", err)
	}

	account, err := createAccount(tx, user.ID, iban)
	if err != nil {
		t.Fatalf("no se pudo crear la cuenta de prueba: %v", err)
	}

	var storedUser struct {
		DNI     []byte
		DNIHash string
	}
	if err := tx.Raw(
		"SELECT dni, dni_hash FROM users WHERE id = ?",
		user.ID,
	).Scan(&storedUser).Error; err != nil {
		t.Fatalf("no se pudo leer la fila cifrada del usuario: %v", err)
	}

	if !models.IsEncryptedValue(storedUser.DNI) {
		t.Fatal("users.dni debe empezar por el byte de versión del sobre cifrado")
	}
	if string(storedUser.DNI) == dni {
		t.Fatal("users.dni no debe contener el DNI en texto plano")
	}
	if expected := models.HashBlindIndex(models.GetDataEncryptionKey(), dni); storedUser.DNIHash != expected {
		t.Fatalf("dni_hash inesperado: %q", storedUser.DNIHash)
	}

	var storedAccount struct {
		IBAN     []byte
		IBANHash string
	}
	if err := tx.Raw(
		"SELECT iban, iban_hash FROM accounts WHERE id = ?",
		account.ID,
	).Scan(&storedAccount).Error; err != nil {
		t.Fatalf("no se pudo leer la fila cifrada de la cuenta: %v", err)
	}

	if !models.IsEncryptedValue(storedAccount.IBAN) {
		t.Fatal("accounts.iban debe empezar por el byte de versión del sobre cifrado")
	}
	if string(storedAccount.IBAN) == iban {
		t.Fatal("accounts.iban no debe contener el IBAN en texto plano")
	}
	if expected := models.HashBlindIndex(models.GetDataEncryptionKey(), iban); storedAccount.IBANHash != expected {
		t.Fatalf("iban_hash inesperado: %q", storedAccount.IBANHash)
	}

	userRepository := NewUserRepository(tx)
	foundUser, err := userRepository.FindByDNI(context.Background(), dni)
	if err != nil || foundUser.ID != user.ID || foundUser.DNI.String() != dni {
		t.Fatalf("FindByDNI no recuperó el DNI descifrado: %v", err)
	}

	accountRepository := NewAccountRepository(tx)
	foundAccount, err := accountRepository.FindByIBAN(context.Background(), iban)
	if err != nil || foundAccount.ID != account.ID || foundAccount.IBAN.String() != iban {
		t.Fatalf("FindByIBAN no recuperó el IBAN descifrado: %v", err)
	}
}

// Los datos que ya existían antes de la migración 000011 están en BYTEA pero
// sin cifrar y sin blind index. El backfill debe cifrarlos y permitir buscarlos.
func TestBackfillEncryptsLegacyPlaintext(t *testing.T) {
	db := connectIntegrationDB(t)
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("no se pudo iniciar la transacción de prueba: %v", tx.Error)
	}
	defer rollback(t, tx)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	dni := "12345678Z"
	iban := fmt.Sprintf("ES91%020d", time.Now().UnixNano())
	email := "legacy-" + suffix + "@securitybank.test"

	var userID int64
	if err := tx.Raw(
		`INSERT INTO users (name, dni, email, password_hash, salt, role)
		 VALUES ('legacy', convert_to(?, 'UTF8'), ?, 'test-password-hash', 'test-salt', 'CLIENT')
		 RETURNING id`,
		dni,
		email,
	).Scan(&userID).Error; err != nil {
		t.Fatalf("no se pudo insertar un usuario heredado: %v", err)
	}

	var accountID int64
	if err := tx.Raw(
		`INSERT INTO accounts (iban, balance)
		 VALUES (convert_to(?, 'UTF8'), 0)
		 RETURNING id`,
		iban,
	).Scan(&accountID).Error; err != nil {
		t.Fatalf("no se pudo insertar una cuenta heredada: %v", err)
	}

	// Antes del backfill: texto plano y sin hash.
	var beforeUser struct {
		DNI     []byte
		DNIHash *string
	}
	if err := tx.Raw(
		"SELECT dni, dni_hash FROM users WHERE id = ?",
		userID,
	).Scan(&beforeUser).Error; err != nil {
		t.Fatalf("no se pudo leer el usuario heredado: %v", err)
	}
	if string(beforeUser.DNI) != dni || beforeUser.DNIHash != nil {
		t.Fatal("el usuario heredado debería estar en texto plano y sin blind index")
	}

	result, err := database.BackfillSensitiveData(context.Background(), tx)
	if err != nil {
		t.Fatalf("el backfill falló: %v", err)
	}
	if result.Users < 1 || result.Accounts < 1 {
		t.Fatalf("el backfill no procesó las filas heredadas: %+v", result)
	}

	var afterUser struct {
		DNI     []byte
		DNIHash string
	}
	if err := tx.Raw(
		"SELECT dni, dni_hash FROM users WHERE id = ?",
		userID,
	).Scan(&afterUser).Error; err != nil {
		t.Fatalf("no se pudo leer el usuario tras el backfill: %v", err)
	}
	if !models.IsEncryptedValue(afterUser.DNI) || string(afterUser.DNI) == dni {
		t.Fatal("el DNI heredado no quedó cifrado")
	}
	if expected := models.HashBlindIndex(models.GetDataEncryptionKey(), dni); afterUser.DNIHash != expected {
		t.Fatalf("dni_hash inesperado tras el backfill: %q", afterUser.DNIHash)
	}

	var afterAccount struct {
		IBAN     []byte
		IBANHash string
	}
	if err := tx.Raw(
		"SELECT iban, iban_hash FROM accounts WHERE id = ?",
		accountID,
	).Scan(&afterAccount).Error; err != nil {
		t.Fatalf("no se pudo leer la cuenta tras el backfill: %v", err)
	}
	if !models.IsEncryptedValue(afterAccount.IBAN) || string(afterAccount.IBAN) == iban {
		t.Fatal("el IBAN heredado no quedó cifrado")
	}
	if expected := models.HashBlindIndex(models.GetDataEncryptionKey(), iban); afterAccount.IBANHash != expected {
		t.Fatalf("iban_hash inesperado tras el backfill: %q", afterAccount.IBANHash)
	}

	// Las búsquedas por DNI e IBAN ya funcionan sobre las filas migradas.
	if _, err := NewUserRepository(tx).FindByDNI(context.Background(), dni); err != nil {
		t.Fatalf("FindByDNI no encuentra el DNI migrado: %v", err)
	}
	if _, err := NewAccountRepository(tx).FindByIBAN(context.Background(), iban); err != nil {
		t.Fatalf("FindByIBAN no encuentra el IBAN migrado: %v", err)
	}

	// El backfill es idempotente: una segunda ejecución no toca nada.
	second, err := database.BackfillSensitiveData(context.Background(), tx)
	if err != nil {
		t.Fatalf("el segundo backfill falló: %v", err)
	}
	if second.Users != 0 || second.Accounts != 0 {
		t.Fatalf("el backfill no es idempotente: %+v", second)
	}
}

// VerifySensitiveDataKey debe aceptar la clave correcta y rechazar otra que no
// pueda descifrar las filas existentes, para que el backend no arranque con
// una clave equivocada.
func TestVerifySensitiveDataKeyDetectsWrongKey(t *testing.T) {
	db := connectIntegrationDB(t)
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("no se pudo iniciar la transacción de prueba: %v", tx.Error)
	}
	defer rollback(t, tx)

	correctKey := models.GetDataEncryptionKey()
	t.Cleanup(func() {
		if err := models.SetDataEncryptionKey(correctKey); err != nil {
			t.Errorf("no se pudo restaurar la clave de pruebas: %v", err)
		}
	})

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &models.User{
		Name:         "clave de verificación",
		DNI:          models.EncryptedString("V" + suffix),
		Email:        "verificacion-" + suffix + "@securitybank.test",
		PasswordHash: "test-password-hash",
		Salt:         "test-salt",
		Role:         models.UserRoleClient,
	}
	if err := tx.Create(user).Error; err != nil {
		t.Fatalf("no se pudo crear el usuario de prueba: %v", err)
	}

	if err := database.VerifySensitiveDataKey(context.Background(), tx); err != nil {
		t.Fatalf("la verificación falló con la clave correcta: %v", err)
	}

	wrongKey := []byte("fedcba9876543210fedcba9876543210")
	if err := models.SetDataEncryptionKey(wrongKey); err != nil {
		t.Fatalf("no se pudo configurar la clave incorrecta: %v", err)
	}

	if err := database.VerifySensitiveDataKey(context.Background(), tx); err == nil {
		t.Fatal("la verificación debería fallar con una clave incorrecta")
	}
}

func connectIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no está disponible para la prueba de integración")
	}

	db, err := database.Connect(databaseURL)
	if err != nil {
		t.Fatalf("no se pudo conectar con la base de datos de prueba: %v", err)
	}
	return db
}

func rollback(t *testing.T, tx *gorm.DB) {
	t.Helper()
	if err := tx.Rollback().Error; err != nil {
		t.Errorf("no se pudo revertir la transacción de prueba: %v", err)
	}
}
