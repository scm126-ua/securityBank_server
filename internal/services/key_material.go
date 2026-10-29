package services

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"securityBank_server/internal/models"
)

const maxEncryptedPrivateKeysSize = 16 * 1024

var ErrInvalidChallengeSignature = errors.New("firma del desafío no válida")
var errInvalidUserSignature = errors.New("firma del usuario no válida")
var ErrKeyMaterialUnavailable = errors.New("el usuario no tiene claves criptográficas")

type PrivateKeyBundle struct {
	Version    int16  `json:"version"`
	Algorithm  string `json:"algorithm"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
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

// Verifica una firma RSA-PSS realizada sobre el desafío recibido.
func verifyChallengeSignature(
	encodedPublicKey string,
	challenge []byte,
	encodedSignature string,
) error {
	signature, err := decodeBase64(encodedSignature)
	if err != nil {
		return ErrInvalidChallengeSignature
	}

	if err := verifyUserSignature(encodedPublicKey, challenge, signature); err != nil {
		return ErrInvalidChallengeSignature
	}

	return nil
}

// Verifica una firma RSA-PSS-SHA256 (sal de 32 bytes) creada con la clave de firma de un usuario.
func verifyUserSignature(
	encodedPublicKey string,
	message []byte,
	signature []byte,
) error {
	_, publicKeyDER, err := validateRSAPublicKey(encodedPublicKey)
	if err != nil {
		return errInvalidUserSignature
	}

	parsed, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return errInvalidUserSignature
	}
	publicKey := parsed.(*rsa.PublicKey)

	if len(signature) != publicKey.Size() {
		return errInvalidUserSignature
	}

	digest := sha256.Sum256(message)
	err = rsa.VerifyPSS(
		publicKey,
		crypto.SHA256,
		digest[:],
		signature,
		&rsa.PSSOptions{
			SaltLength: 32,
			Hash:       crypto.SHA256,
		},
	)
	if err != nil {
		return errInvalidUserSignature
	}

	return nil
}

// Prepara el paquete cifrado del usuario para enviarlo al cliente autenticado.
func PrivateKeyBundleForUser(user *models.User) (PrivateKeyBundle, error) {
	if user.PublicKey == nil ||
		user.SigningPublicKey == nil ||
		len(user.EncryptedPrivateKeys) < 16 ||
		len(user.PrivateKeysSalt) != 16 ||
		len(user.PrivateKeysNonce) != 12 ||
		user.PrivateKeysIterations == nil ||
		user.PrivateKeysVersion == nil {
		return PrivateKeyBundle{}, ErrKeyMaterialUnavailable
	}

	return PrivateKeyBundle{
		Version:    *user.PrivateKeysVersion,
		Algorithm:  "AES-256-GCM",
		KDF:        "PBKDF2-HMAC-SHA256",
		Iterations: *user.PrivateKeysIterations,
		Salt:       base64.StdEncoding.EncodeToString(user.PrivateKeysSalt),
		Nonce:      base64.StdEncoding.EncodeToString(user.PrivateKeysNonce),
		Ciphertext: base64.StdEncoding.EncodeToString(user.EncryptedPrivateKeys),
	}, nil
}
