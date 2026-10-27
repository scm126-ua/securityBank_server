package services

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

const maxEncryptedPrivateKeysSize = 16 * 1024

type PrivateKeyBundle struct {
	Version    int16
	Algorithm  string
	KDF        string
	Iterations int
	Salt       string
	Nonce      string
	Ciphertext string
}

type UserKeyMaterial struct {
	PublicKey        string
	SigningPublicKey string
	PrivateKeys      PrivateKeyBundle
}

type validatedUserKeyMaterial struct {
	publicKey        string
	signingPublicKey string
	ciphertext       []byte
	salt             []byte
	nonce            []byte
	iterations       int
	version          int16
}

// Valida las claves públicas y prepara el paquete privado para almacenarlo.
func validateUserKeyMaterial(material UserKeyMaterial) (*validatedUserKeyMaterial, error) {
	publicKey, publicKeyDER, err := validateRSAPublicKey(material.PublicKey)
	if err != nil {
		return nil, err
	}

	signingPublicKey, signingPublicKeyDER, err := validateRSAPublicKey(material.SigningPublicKey)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(publicKeyDER, signingPublicKeyDER) {
		return nil, fmt.Errorf("%w: las claves públicas deben ser distintas", ErrInvalidKeyMaterial)
	}

	bundle := material.PrivateKeys
	if bundle.Version != 1 ||
		bundle.Algorithm != "AES-256-GCM" ||
		bundle.KDF != "PBKDF2-HMAC-SHA256" ||
		bundle.Iterations != 600000 {
		return nil, fmt.Errorf("%w: formato de paquete no compatible", ErrInvalidKeyMaterial)
	}

	salt, err := decodeBase64(bundle.Salt)
	if err != nil || len(salt) != 16 {
		return nil, fmt.Errorf("%w: sal incorrecta", ErrInvalidKeyMaterial)
	}

	nonce, err := decodeBase64(bundle.Nonce)
	if err != nil || len(nonce) != 12 {
		return nil, fmt.Errorf("%w: nonce incorrecto", ErrInvalidKeyMaterial)
	}

	ciphertext, err := decodeBase64(bundle.Ciphertext)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > maxEncryptedPrivateKeysSize {
		return nil, fmt.Errorf("%w: claves privadas cifradas incorrectas", ErrInvalidKeyMaterial)
	}

	return &validatedUserKeyMaterial{
		publicKey:        publicKey,
		signingPublicKey: signingPublicKey,
		ciphertext:       ciphertext,
		salt:             salt,
		nonce:            nonce,
		iterations:       bundle.Iterations,
		version:          bundle.Version,
	}, nil
}

// Comprueba que una clave pública sea RSA-3072 en formato SPKI.
func validateRSAPublicKey(value string) (string, []byte, error) {
	decoded, err := decodeBase64(value)
	if err != nil {
		return "", nil, fmt.Errorf("%w: clave pública en Base64 incorrecta", ErrInvalidKeyMaterial)
	}

	parsed, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return "", nil, fmt.Errorf("%w: clave pública SPKI incorrecta", ErrInvalidKeyMaterial)
	}

	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() != 3072 || publicKey.E != 65537 {
		return "", nil, fmt.Errorf("%w: se requiere una clave RSA-3072", ErrInvalidKeyMaterial)
	}

	return base64.StdEncoding.EncodeToString(decoded), decoded, nil
}

// Decodifica Base64 rechazando caracteres o rellenos no válidos.
func decodeBase64(value string) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(value)
}
