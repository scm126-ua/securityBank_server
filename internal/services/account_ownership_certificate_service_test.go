package services

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Comprueba que un certificado recién emitido puede verificarse con la clave pública del servidor.
func TestAccountOwnershipCertificateCanBeVerified(t *testing.T) {
	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar la clave de prueba: %v", err)
	}

	signedCertificate, err := CreateAccountOwnershipCertificate(
		serverPrivateKey,
		AccountOwnershipData{
			HolderID:   7,
			HolderName: "Ana Ejemplo",
			HolderDNI:  "12345678Z",
			AccountID:  12,
			IBAN:       "ES85 0036 1234 1441 2259 7803",
			Role:       "OWNER",
		},
	)
	if err != nil {
		t.Fatalf("no se pudo crear el certificado: %v", err)
	}

	if err := VerifyAccountOwnershipCertificate(
		&serverPrivateKey.PublicKey,
		signedCertificate,
	); err != nil {
		t.Fatalf("el certificado válido fue rechazado: %v", err)
	}
	if len(signedCertificate.Certificate.CertificateID) != 22 {
		t.Fatal("el identificador del certificado no tiene 128 bits")
	}
	if signedCertificate.Certificate.IBAN != "ES8500361234144122597803" {
		t.Fatal("el IBAN no se normalizó antes de firmarlo")
	}
}

// Comprueba que modificar cualquier dato representativo invalida la firma del certificado.
func TestAccountOwnershipCertificateRejectsTampering(t *testing.T) {
	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar la clave de prueba: %v", err)
	}

	original, err := CreateAccountOwnershipCertificate(
		serverPrivateKey,
		AccountOwnershipData{
			HolderID:   7,
			HolderName: "Ana Ejemplo",
			HolderDNI:  "12345678Z",
			AccountID:  12,
			IBAN:       "ES8500361234144122597803",
			Role:       "OWNER",
		},
	)
	if err != nil {
		t.Fatalf("no se pudo crear el certificado: %v", err)
	}

	changedHolder := original
	changedHolder.Certificate.HolderName = "Otra Persona"
	changedDNI := original
	changedDNI.Certificate.HolderDNI = "00000000T"
	changedAccount := original
	changedAccount.Certificate.AccountID = 99
	changedIBAN := original
	changedIBAN.Certificate.IBAN = "ES0000000000000000000000"
	changedRole := original
	changedRole.Certificate.Role = "CO_OWNER"

	tests := []struct {
		name        string
		certificate SignedAccountOwnershipCertificate
	}{
		{name: "titular modificado", certificate: changedHolder},
		{name: "DNI modificado", certificate: changedDNI},
		{name: "cuenta modificada", certificate: changedAccount},
		{name: "IBAN modificado", certificate: changedIBAN},
		{name: "rol modificado", certificate: changedRole},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyAccountOwnershipCertificate(
				&serverPrivateKey.PublicKey,
				test.certificate,
			); err == nil {
				t.Fatal("se aceptó un certificado manipulado")
			}
		})
	}
}
