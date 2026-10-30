package services

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTOTPEncryptionDecryption(t *testing.T) {
	keyStr := "DuLMfen6unn7Nhmb3WMxo+xibIJS3LXo0dr3VaOcoMY="
	keyBytes, err := DecodeTOTPEncryptionKey(keyStr)
	if err != nil {
		t.Fatalf("error decodificando clave: %v", err)
	}

	_, err = NewTOTPService(nil, keyBytes)
	// NewTOTPService requires repo != nil, but we can test encryption/decryption logic
	if err != ErrTOTPEncryption {
		t.Fatalf("esperaba ErrTOTPEncryption con repo nil")
	}
}

func TestTOTPGenerateAndValidate(t *testing.T) {
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i)
	}

	// Create dummy service by assigning cipherKey directly for encryption tests
	svc := &TOTPService{
		cipherKey: keyBytes,
	}

	secret := "JBSWY3DPEHPK3PXP"
	encrypted, err := svc.EncryptSecret(secret)
	if err != nil {
		t.Fatalf("error cifrando secreto: %v", err)
	}

	decrypted, err := svc.DecryptSecret(encrypted)
	if err != nil {
		t.Fatalf("error descifrando secreto: %v", err)
	}

	if decrypted != secret {
		t.Fatalf("secreto descifrado '%s' no coincide con original '%s'", decrypted, secret)
	}

	// Test Registration TOTP generation
	res, err := svc.GenerateRegistrationTOTP("test@securitybank.es")
	if err != nil {
		t.Fatalf("error generando TOTP de registro: %v", err)
	}

	if res.Secret == "" || !strings.HasPrefix(res.OtpauthURL, "otpauth://totp/") || !strings.HasPrefix(res.QRCode, "data:image/png;base64,") {
		t.Fatalf("respuesta de configuración inválida: %+v", res)
	}

	// Generate a valid TOTP code
	code, err := totp.GenerateCode(res.Secret, time.Now())
	if err != nil {
		t.Fatalf("error generando código TOTP: %v", err)
	}

	valid, err := svc.ValidateCode(res.Secret, code)
	if err != nil || !valid {
		t.Fatalf("el código generado debería ser válido: %v", err)
	}

	// Invalid code test
	invalid, _ := svc.ValidateCode(res.Secret, "000000")
	if invalid && code != "000000" {
		t.Fatalf("el código 000000 no debería ser válido")
	}
}

func TestDecodeTOTPEncryptionKey(t *testing.T) {
	key := make([]byte, 32)
	encoded := base64.StdEncoding.EncodeToString(key)

	decoded, err := DecodeTOTPEncryptionKey(encoded)
	if err != nil {
		t.Fatalf("no se pudo decodificar clave válida: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("longitud de clave incorrecta: %d", len(decoded))
	}

	// Invalid length
	invalidEncoded := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := DecodeTOTPEncryptionKey(invalidEncoded); err == nil {
		t.Fatalf("debería fallar con clave corta")
	}
}
