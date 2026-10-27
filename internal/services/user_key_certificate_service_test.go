package services

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Comprueba que el servidor puede certificar y verificar las claves de un usuario.
func TestUserPublicKeysSignature(t *testing.T) {
	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar la clave de prueba: %v", err)
	}

	signature, err := SignUserPublicKeys(
		serverPrivateKey,
		"USER@EXAMPLE.COM ",
		"encryption-public-key",
		"signing-public-key",
	)
	if err != nil {
		t.Fatalf("no se pudieron firmar las claves: %v", err)
	}

	err = VerifyUserPublicKeys(
		&serverPrivateKey.PublicKey,
		"user@example.com",
		"encryption-public-key",
		"signing-public-key",
		signature,
	)
	if err != nil {
		t.Fatalf("la firma válida fue rechazada: %v", err)
	}
}

// Comprueba que cualquier sustitución de los datos certificados invalida la firma.
func TestUserPublicKeysSignatureRejectsChanges(t *testing.T) {
	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar la clave de prueba: %v", err)
	}

	signature, err := SignUserPublicKeys(
		serverPrivateKey,
		"user@example.com",
		"encryption-public-key",
		"signing-public-key",
	)
	if err != nil {
		t.Fatalf("no se pudieron firmar las claves: %v", err)
	}

	tests := []struct {
		name             string
		email            string
		publicKey        string
		signingPublicKey string
	}{
		{
			name:             "correo sustituido",
			email:            "other@example.com",
			publicKey:        "encryption-public-key",
			signingPublicKey: "signing-public-key",
		},
		{
			name:             "clave de cifrado sustituida",
			email:            "user@example.com",
			publicKey:        "other-encryption-public-key",
			signingPublicKey: "signing-public-key",
		},
		{
			name:             "clave de firma sustituida",
			email:            "user@example.com",
			publicKey:        "encryption-public-key",
			signingPublicKey: "other-signing-public-key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := VerifyUserPublicKeys(
				&serverPrivateKey.PublicKey,
				test.email,
				test.publicKey,
				test.signingPublicKey,
				signature,
			)
			if err == nil {
				t.Fatal("se aceptaron datos diferentes a los certificados")
			}
		})
	}
}
