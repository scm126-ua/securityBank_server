package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const userKeyCertificateVersion = "securitybank-user-keys-v1"

// Firma la identidad del usuario y sus dos claves públicas con la identidad del servidor.
func SignUserPublicKeys(
	serverPrivateKey *rsa.PrivateKey,
	email string,
	publicKey string,
	signingPublicKey string,
) (string, error) {
	if serverPrivateKey == nil {
		return "", errors.New("la clave privada del servidor no está disponible")
	}

	payload := userKeyCertificatePayload(email, publicKey, signingPublicKey)
	digest := sha256.Sum256(payload)

	signature, err := rsa.SignPSS(
		rand.Reader,
		serverPrivateKey,
		crypto.SHA256,
		digest[:],
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)
	if err != nil {
		return "", fmt.Errorf("no se pudieron firmar las claves públicas: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// Comprueba que las claves públicas pertenecen a la identidad certificada por el servidor.
func VerifyUserPublicKeys(
	serverPublicKey *rsa.PublicKey,
	email string,
	publicKey string,
	signingPublicKey string,
	encodedSignature string,
) error {
	if serverPublicKey == nil {
		return errors.New("la clave pública del servidor no está disponible")
	}

	signature, err := base64.StdEncoding.Strict().DecodeString(encodedSignature)
	if err != nil {
		return errors.New("la firma de las claves públicas no está codificada correctamente")
	}

	payload := userKeyCertificatePayload(email, publicKey, signingPublicKey)
	digest := sha256.Sum256(payload)

	if err := rsa.VerifyPSS(
		serverPublicKey,
		crypto.SHA256,
		digest[:],
		signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	); err != nil {
		return errors.New("la firma de las claves públicas no es válida")
	}

	return nil
}

// Construye una representación inequívoca y versionada de los datos que se firman.
func userKeyCertificatePayload(email string, publicKey string, signingPublicKey string) []byte {
	fields := []string{
		userKeyCertificateVersion,
		strings.ToLower(strings.TrimSpace(email)),
		publicKey,
		signingPublicKey,
	}

	payload := make([]byte, 0)
	for _, field := range fields {
		encodedLength := make([]byte, 4)
		binary.BigEndian.PutUint32(encodedLength, uint32(len(field)))
		payload = append(payload, encodedLength...)
		payload = append(payload, field...)
	}

	return payload
}
