package models

import (
	"bytes"
	"encoding/json"
	"testing"
)

var testDataKey = []byte("01234567890123456789012345678901") // 32 bytes

func TestSetDataEncryptionKeyRejectsInvalidLength(t *testing.T) {
	if err := SetDataEncryptionKey([]byte("demasiado corta")); err == nil {
		t.Fatal("se esperaba un error con una clave que no tiene 32 bytes")
	}

	if err := SetDataEncryptionKey(testDataKey); err != nil {
		t.Fatalf("no se pudo configurar una clave válida: %v", err)
	}
}

func TestEncryptedStringValueAndScan(t *testing.T) {
	if err := SetDataEncryptionKey(testDataKey); err != nil {
		t.Fatalf("no se pudo configurar la clave: %v", err)
	}

	originalDNI := EncryptedString("12345678Z")

	// 1. Value() debe devolver ciphertext cifrado con AES-GCM.
	val, err := originalDNI.Value()
	if err != nil {
		t.Fatalf("error cifrando con Value(): %v", err)
	}

	ciphertext, ok := val.([]byte)
	if !ok {
		t.Fatalf("se esperaba []byte de Value(), obtenido %T", val)
	}

	if !IsEncryptedValue(ciphertext) {
		t.Fatal("el valor almacenado debe incluir el byte de versión del sobre")
	}

	if bytes.Contains(ciphertext, []byte("12345678Z")) {
		t.Fatal("el ciphertext no debe contener el DNI en texto plano")
	}

	// versión (1) + nonce (12) + payload (9) + tag GCM (16) = 38 bytes
	if len(ciphertext) < 1+12+9+16 {
		t.Fatalf("longitud de ciphertext demasiado corta: %d", len(ciphertext))
	}

	// 2. Dos llamadas a Value() deben generar ciphertexts distintos (nonce aleatorio).
	val2, err := originalDNI.Value()
	if err != nil {
		t.Fatalf("error en segunda llamada a Value(): %v", err)
	}
	ciphertext2 := val2.([]byte)
	if bytes.Equal(ciphertext, ciphertext2) {
		t.Fatal("AES-GCM debe usar un nonce aleatorio diferente en cada cifrado")
	}

	// 3. Scan() debe descifrar correctamente el ciphertext original.
	var decryptedDNI EncryptedString
	if err := decryptedDNI.Scan(ciphertext); err != nil {
		t.Fatalf("error descifrando con Scan(): %v", err)
	}
	if decryptedDNI.String() != "12345678Z" {
		t.Fatalf("esperado '12345678Z', obtenido '%s'", decryptedDNI.String())
	}

	// 4. Scan() del segundo ciphertext también debe dar el mismo texto plano.
	var decryptedDNI2 EncryptedString
	if err := decryptedDNI2.Scan(ciphertext2); err != nil {
		t.Fatalf("error descifrando segundo ciphertext: %v", err)
	}
	if decryptedDNI2.String() != "12345678Z" {
		t.Fatalf("esperado '12345678Z', obtenido '%s'", decryptedDNI2.String())
	}
}

func TestEncryptedIBAN(t *testing.T) {
	if err := SetDataEncryptionKey(testDataKey); err != nil {
		t.Fatalf("no se pudo configurar la clave: %v", err)
	}

	originalIBAN := EncryptedString("ES8500361234144122597803")

	val, err := originalIBAN.Value()
	if err != nil {
		t.Fatalf("error en Value() de IBAN: %v", err)
	}
	ciphertext := val.([]byte)

	if bytes.Contains(ciphertext, []byte("ES85")) {
		t.Fatal("el ciphertext no debe contener el IBAN en texto plano")
	}

	var decryptedIBAN EncryptedString
	if err := decryptedIBAN.Scan(ciphertext); err != nil {
		t.Fatalf("error en Scan() de IBAN: %v", err)
	}
	if decryptedIBAN.String() != "ES8500361234144122597803" {
		t.Fatalf("esperado IBAN descifrado correcto, obtenido '%s'", decryptedIBAN.String())
	}
}

func TestEncryptedStringRejectsWrongKeyAndTampering(t *testing.T) {
	if err := SetDataEncryptionKey(testDataKey); err != nil {
		t.Fatalf("no se pudo configurar la clave: %v", err)
	}

	val, err := EncryptedString("12345678Z").Value()
	if err != nil {
		t.Fatalf("error cifrando: %v", err)
	}
	ciphertext := val.([]byte)

	// Clave distinta: GCM debe fallar y Scan debe devolver error.
	if err := SetDataEncryptionKey([]byte("98765432109876543210987654321098")); err != nil {
		t.Fatalf("no se pudo cambiar la clave: %v", err)
	}
	var wrongKeyResult EncryptedString
	if err := wrongKeyResult.Scan(ciphertext); err == nil {
		t.Fatal("descifrar con otra clave debe devolver un error, no el ciphertext")
	}

	// Volvemos a la clave correcta y manipulamos un byte del ciphertext.
	if err := SetDataEncryptionKey(testDataKey); err != nil {
		t.Fatalf("no se pudo restaurar la clave: %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF

	var tamperedResult EncryptedString
	if err := tamperedResult.Scan(tampered); err == nil {
		t.Fatal("un ciphertext manipulado debe ser rechazado por GCM")
	}
}

func TestEncryptedStringReadsLegacyPlaintext(t *testing.T) {
	if err := SetDataEncryptionKey(testDataKey); err != nil {
		t.Fatalf("no se pudo configurar la clave: %v", err)
	}

	var legacy EncryptedString
	if err := legacy.Scan([]byte("12345678Z")); err != nil {
		t.Fatalf("los datos heredados en texto plano deben poder leerse: %v", err)
	}
	if legacy.String() != "12345678Z" {
		t.Fatalf("esperado '12345678Z', obtenido '%s'", legacy.String())
	}
}

func TestEncryptedStringJSON(t *testing.T) {
	original := EncryptedString("ES8500361234144122597803")

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("error serializando a JSON: %v", err)
	}
	if string(encoded) != `"ES8500361234144122597803"` {
		t.Fatalf("JSON inesperado: %s", encoded)
	}

	var decoded EncryptedString
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("error deserializando JSON: %v", err)
	}
	if decoded != original {
		t.Fatalf("esperado '%s', obtenido '%s'", original, decoded)
	}
}

func TestEncryptedStringWithoutKeyFailsClosed(t *testing.T) {
	sensitiveDataKeyMutex.Lock()
	previous := sensitiveDataKey
	sensitiveDataKey = nil
	sensitiveDataKeyMutex.Unlock()
	defer func() {
		sensitiveDataKeyMutex.Lock()
		sensitiveDataKey = previous
		sensitiveDataKeyMutex.Unlock()
	}()

	if _, err := (EncryptedString("12345678Z")).Value(); err == nil {
		t.Fatal("cifrar sin clave configurada debe devolver un error")
	}

	var value EncryptedString
	if err := value.Scan([]byte{sensitiveValueVersion, 1, 2, 3}); err == nil {
		t.Fatal("descifrar sin clave configurada debe devolver un error")
	}

	if got := HashBlindIndex(nil, "12345678Z"); got != "" {
		t.Fatalf("sin clave no debe generarse un blind index, obtenido %q", got)
	}
}

func TestHashBlindIndex(t *testing.T) {
	// El blind index debe ser determinista e insensible a espacios y mayúsculas.
	hash1 := HashBlindIndex(testDataKey, "ES85 0036 1234 1441 2259 7803")
	hash2 := HashBlindIndex(testDataKey, "es8500361234144122597803")
	hash3 := HashBlindIndex(testDataKey, " ES8500361234144122597803 ")

	if hash1 == "" || hash1 != hash2 || hash2 != hash3 {
		t.Fatalf("HashBlindIndex debe generar el mismo hash normalizado: %s, %s, %s", hash1, hash2, hash3)
	}

	// Longitud SHA256 hex = 64 caracteres.
	if len(hash1) != 64 {
		t.Fatalf("longitud de hash incorrecta: %d", len(hash1))
	}

	// Diferente entrada debe generar diferente hash.
	diffHash := HashBlindIndex(testDataKey, "ES9900000000000000000000")
	if diffHash == hash1 {
		t.Fatal("diferentes IBAN deben generar diferentes blind indexes")
	}

	// Diferente clave debe generar diferente blind index.
	otherKeyHash := HashBlindIndex([]byte("98765432109876543210987654321098"), "ES8500361234144122597803")
	if otherKeyHash == hash1 {
		t.Fatal("el blind index debe depender de la clave")
	}
}

func TestNormalizeSensitiveValue(t *testing.T) {
	if got := NormalizeSensitiveValue("  es85\t0036 1234 "); got != "ES8500361234" {
		t.Fatalf("normalización inesperada: %q", got)
	}
}
