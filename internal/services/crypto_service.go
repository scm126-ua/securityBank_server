package services

// POR IMPLEMENTAR

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/pbkdf2"
)

// Encripta y cifra texto plano usando AES-256-GCM devolviendo nonce,
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 necesita una clave de 32 bytes")
	}

	// Creamos un nuevo bloque de cifrado
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Creamos un nuevo GCM (Galois/Counter Mode) para el cifrado
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generamos un nonce aleatorio
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Ciframos el texto plano y devolvemos el texto cifrado con el nonce
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Desencripta y descifra texto cifrado devolviendo texto plano
func Decrypt(key, data []byte) ([]byte, error) {

	if len(key) != 32 {
		return nil, errors.New("AES-256 necesita una clave de 32 bytes")
	}

	// Creamos un nuevo bloque de cifrado
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Creamos un nuevo GCM (Galois/Counter Mode) para el descifrado
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Si el texto cifrado es demasiado corto, devolvemos un error
	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("El texto cifrado es demasiado corto")
	}
	// Separamos el nonce del texto cifrado
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	// Desciframos el texto cifrado y devolvemos el texto plano
	return gcm.Open(nil, nonce, ct, nil)
}

// Función para hashing de contraseñas con derivación de clave PBKDF2 y salt aleatorio
func HashPassword(password string) (string, string, error) {
    salt := make([]byte, 16)

    if _, err := rand.Read(salt); err != nil {
        return "", "", err
    }

	iteraciones := 600000
	keyLen := 32

    hash := pbkdf2.Key(
        []byte(password),
        salt,
        iteraciones,
        keyLen,
        sha256.New,
    )

    return hex.EncodeToString(hash),
        hex.EncodeToString(salt),
        nil
}

// Verifica que la contraseña proporcionada coincide con el hash almacenado
func VerifyPassword(password, storedHash, storedSalt string) (bool, error) {
    salt, err := hex.DecodeString(storedSalt)
    if err != nil {
        return false, err
    }

    expectedHash, err := hex.DecodeString(storedHash)
    if err != nil {
        return false, err
    }

    if len(salt) != 16 || len(expectedHash) != 32 {
        return false, errors.New("formato de hash inválido")
    }

    actualHash := pbkdf2.Key(
        []byte(password),
        salt,
        600000,
        32,
        sha256.New,
    )

    return hmac.Equal(actualHash, expectedHash), nil
}
