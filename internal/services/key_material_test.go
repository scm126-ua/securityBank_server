package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
)

// Comprueba firmas válidas, manipuladas y creadas con otra clave.
func TestChallengeSignatureVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("no se pudo generar la clave de prueba: %v", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("no se pudo exportar la clave pública: %v", err)
	}
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicKeyDER)

	challenge := make([]byte, challengeRandomSize)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatalf("no se pudo generar el desafío de prueba: %v", err)
	}

	digest := sha256.Sum256(challenge)
	signature, err := rsa.SignPSS(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		digest[:],
		&rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256},
	)
	if err != nil {
		t.Fatalf("no se pudo firmar el desafío: %v", err)
	}
	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	if err := verifyChallengeSignature(encodedPublicKey, challenge, encodedSignature); err != nil {
		t.Fatalf("la firma correcta debería aceptarse: %v", err)
	}

	tamperedChallenge := append([]byte(nil), challenge...)
	tamperedChallenge[0] ^= 1
	if err := verifyChallengeSignature(encodedPublicKey, tamperedChallenge, encodedSignature); !errors.Is(err, ErrInvalidChallengeSignature) {
		t.Fatal("un desafío manipulado debería rechazarse")
	}

	otherPrivateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("no se pudo generar la segunda clave de prueba: %v", err)
	}
	otherSignature, err := rsa.SignPSS(
		rand.Reader,
		otherPrivateKey,
		crypto.SHA256,
		digest[:],
		&rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256},
	)
	if err != nil {
		t.Fatalf("no se pudo crear la firma ajena: %v", err)
	}
	if err := verifyChallengeSignature(
		encodedPublicKey,
		challenge,
		base64.StdEncoding.EncodeToString(otherSignature),
	); !errors.Is(err, ErrInvalidChallengeSignature) {
		t.Fatal("una firma creada con otra clave debería rechazarse")
	}

	if err := verifyChallengeSignature(encodedPublicKey, challenge, "no-es-base64"); !errors.Is(err, ErrInvalidChallengeSignature) {
		t.Fatal("una firma mal codificada debería rechazarse")
	}
}
