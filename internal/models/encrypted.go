package models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	// Versión del sobre cifrado que se guarda en las columnas BYTEA.
	// Permite cambiar el formato (o la clave) en el futuro sin ambigüedad.
	sensitiveValueVersion byte = 1

	// Datos adicionales autenticados (AAD): vinculan el cifrado a este uso
	// concreto. Si un atacante intenta reutilizarlo en otro contexto con una
	// versión/AAD distinta, GCM rechaza el descifrado.
	sensitiveValueAAD = "securitybank:sensitive-value:v1"

	// Etiqueta usada para derivar una subclave independiente del blind index.
	// El cifrado AES-GCM y el HMAC-SHA256 nunca comparten la misma clave.
	blindIndexKeyLabel = "securitybank:blind-index:v1"
)

var (
	sensitiveDataKeyMutex sync.RWMutex
	sensitiveDataKey      []byte

	ErrDataEncryptionKeyNotConfigured = errors.New("la clave de cifrado de datos sensibles no está configurada")
	ErrInvalidDataEncryptionKey       = errors.New("la clave de cifrado de datos sensibles debe tener 32 bytes (AES-256)")
)

// SetDataEncryptionKey configura la clave AES-256 (32 bytes) para cifrar DNI e IBAN.
// La clave se copia para que el llamante no pueda modificarla después.
func SetDataEncryptionKey(key []byte) error {
	if len(key) != 32 {
		return ErrInvalidDataEncryptionKey
	}

	sensitiveDataKeyMutex.Lock()
	defer sensitiveDataKeyMutex.Unlock()

	sensitiveDataKey = make([]byte, len(key))
	copy(sensitiveDataKey, key)
	return nil
}

// GetDataEncryptionKey devuelve una copia de la clave activa o nil si aún no
// se ha configurado. Nunca se usa una clave por defecto: si falta la variable
// de entorno, el backend no arranca en lugar de cifrar con una clave pública.
func GetDataEncryptionKey() []byte {
	sensitiveDataKeyMutex.RLock()
	defer sensitiveDataKeyMutex.RUnlock()

	if len(sensitiveDataKey) != 32 {
		return nil
	}

	keyCopy := make([]byte, len(sensitiveDataKey))
	copy(keyCopy, sensitiveDataKey)
	return keyCopy
}

// EncryptAESGCM cifra datos usando AES-256-GCM y antepone el nonce aleatorio
// de 12 bytes: [nonce(12)][ciphertext][tag(16)].
func EncryptAESGCM(key, plaintext []byte) ([]byte, error) {
	return encryptAESGCM(key, plaintext, nil)
}

// DecryptAESGCM descifra datos en formato [nonce(12)][ciphertext][tag(16)].
func DecryptAESGCM(key, data []byte) ([]byte, error) {
	return decryptAESGCM(key, data, nil)
}

func encryptAESGCM(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidDataEncryptionKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func decryptAESGCM(key, data, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidDataEncryptionKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize+gcm.Overhead() {
		return nil, errors.New("el texto cifrado es demasiado corto")
	}

	nonce, ct := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ct, aad)
}

// encryptSensitiveValue cifra un valor y lo envuelve con el byte de versión:
// [versión(1)][nonce(12)][ciphertext][tag(16)].
func encryptSensitiveValue(key, plaintext []byte) ([]byte, error) {
	payload, err := encryptAESGCM(key, plaintext, []byte(sensitiveValueAAD))
	if err != nil {
		return nil, err
	}

	envelope := make([]byte, 0, 1+len(payload))
	envelope = append(envelope, sensitiveValueVersion)
	envelope = append(envelope, payload...)
	return envelope, nil
}

// decryptSensitiveValue descifra un sobre con versión y AAD.
func decryptSensitiveValue(key, envelope []byte) ([]byte, error) {
	if len(envelope) < 2 || envelope[0] != sensitiveValueVersion {
		return nil, errors.New("versión de cifrado desconocida")
	}

	return decryptAESGCM(key, envelope[1:], []byte(sensitiveValueAAD))
}

// IsEncryptedValue indica si un valor almacenado usa el sobre cifrado actual.
// Los valores heredados en texto plano (anteriores a la migración 000011) no
// llevan el byte de versión.
func IsEncryptedValue(data []byte) bool {
	return len(data) > 0 && data[0] == sensitiveValueVersion
}

// HashBlindIndex calcula un HMAC-SHA256 determinista para indexar y buscar
// valores exactos (DNI e IBAN) sin descifrarlos. Se normaliza el valor para
// que "ES85 0036..." y "es850036..." produzcan el mismo índice.
//
// El HMAC usa una subclave derivada de la clave maestra, de modo que el mismo
// material de clave nunca se reutiliza directamente en AES-GCM y HMAC.
func HashBlindIndex(key []byte, data string) string {
	if len(key) != 32 {
		return ""
	}

	normalized := NormalizeSensitiveValue(data)
	if normalized == "" {
		return ""
	}

	h := hmac.New(sha256.New, deriveSubkey(key, blindIndexKeyLabel))
	h.Write([]byte(normalized))
	return hex.EncodeToString(h.Sum(nil))
}

// NormalizeSensitiveValue elimina espacios y unifica mayúsculas. Es la misma
// normalización que se usa antes de guardar y al buscar por blind index.
func NormalizeSensitiveValue(value string) string {
	return strings.ToUpper(strings.Join(strings.Fields(strings.TrimSpace(value)), ""))
}

func deriveSubkey(key []byte, label string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// EncryptedString es un tipo que en memoria y JSON se comporta como string en texto plano,
// pero que al persistirse en base de datos se cifra automáticamente con AES-256-GCM.
type EncryptedString string

// Value implementa driver.Valuer: cifra el texto plano antes de escribir en la base de datos.
func (e EncryptedString) Value() (driver.Value, error) {
	str := string(e)
	if str == "" {
		return nil, nil
	}

	key := GetDataEncryptionKey()
	if len(key) != 32 {
		return nil, ErrDataEncryptionKeyNotConfigured
	}

	ciphertext, err := encryptSensitiveValue(key, []byte(str))
	if err != nil {
		return nil, fmt.Errorf("cifrado AES-GCM falló: %w", err)
	}
	return ciphertext, nil
}

// Scan implementa sql.Scanner: descifra el texto cifrado leído de la base de datos.
//
// Si el valor no empieza por el byte de versión, se asume que es un dato
// heredado en texto plano (anterior a la migración 000011). Esos datos se
// siguen pudiendo leer y el backfill de arranque los vuelve a cifrar. En
// cambio, un sobre cifrado cuya autenticación GCM falle (clave incorrecta o
// manipulación) devuelve un error: nunca se expone el ciphertext como si
// fuera el DNI o el IBAN.
func (e *EncryptedString) Scan(src interface{}) error {
	if src == nil {
		*e = ""
		return nil
	}

	var raw []byte
	switch v := src.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("tipo no compatible con EncryptedString: %T", src)
	}

	if len(raw) == 0 {
		*e = ""
		return nil
	}

	if !IsEncryptedValue(raw) {
		// Compatibilidad con datos anteriores al cifrado.
		*e = EncryptedString(raw)
		return nil
	}

	key := GetDataEncryptionKey()
	if len(key) != 32 {
		return ErrDataEncryptionKeyNotConfigured
	}

	plaintext, err := decryptSensitiveValue(key, raw)
	if err != nil {
		return fmt.Errorf("no se pudo descifrar el valor sensible: %w", err)
	}

	*e = EncryptedString(plaintext)
	return nil
}

// GormDataType especifica a GORM que la columna subyacente es de tipo binario (BYTEA).
func (EncryptedString) GormDataType() string {
	return "bytes"
}

// String devuelve la representación en string en texto plano.
func (e EncryptedString) String() string {
	return string(e)
}

// MarshalJSON asegura que las respuestas JSON expongan el valor descifrado.
func (e EncryptedString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(e))
}

// UnmarshalJSON deserializa el string desde JSON.
func (e *EncryptedString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*e = EncryptedString(s)
	return nil
}
