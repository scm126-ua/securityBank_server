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
	"strconv"
	"strings"
	"time"

	"securityBank_server/internal/models"
)

const accountOwnershipCertificateVersion = 1
const accountOwnershipCertificateContext = "securitybank-account-ownership-v1"

type AccountOwnershipData struct {
	HolderID   int64
	HolderName string
	HolderDNI  string
	AccountID  int64
	IBAN       string
	Role       string
}

type AccountOwnershipCertificate struct {
	Version       int    `json:"version"`
	CertificateID string `json:"certificate_id"`
	IssuedAt      string `json:"issued_at"`
	HolderID      int64  `json:"holder_id"`
	HolderName    string `json:"holder_name"`
	HolderDNI     string `json:"holder_dni"`
	AccountID     int64  `json:"account_id"`
	IBAN          string `json:"iban"`
	Role          string `json:"role"`
}

type SignedAccountOwnershipCertificate struct {
	Certificate        AccountOwnershipCertificate `json:"certificate"`
	SignatureAlgorithm string                      `json:"signature_algorithm"`
	Signature          string                      `json:"signature"`
}

// Genera un certificado de titularidad y lo firma con la identidad del servidor.
func CreateAccountOwnershipCertificate(
	serverPrivateKey *rsa.PrivateKey,
	data AccountOwnershipData,
) (SignedAccountOwnershipCertificate, error) {
	if serverPrivateKey == nil {
		return SignedAccountOwnershipCertificate{}, errors.New("la clave privada del servidor no está disponible")
	}
	if err := validateAccountOwnershipData(data); err != nil {
		return SignedAccountOwnershipCertificate{}, err
	}

	certificateID, err := randomCertificateID()
	if err != nil {
		return SignedAccountOwnershipCertificate{}, err
	}

	certificate := AccountOwnershipCertificate{
		Version:       accountOwnershipCertificateVersion,
		CertificateID: certificateID,
		IssuedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		HolderID:      data.HolderID,
		HolderName:    strings.TrimSpace(data.HolderName),
		HolderDNI:     strings.ToUpper(strings.TrimSpace(data.HolderDNI)),
		AccountID:     data.AccountID,
		IBAN:          strings.ToUpper(strings.ReplaceAll(data.IBAN, " ", "")),
		Role:          data.Role,
	}

	digest := sha256.Sum256(accountOwnershipCertificatePayload(certificate))
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
		return SignedAccountOwnershipCertificate{}, fmt.Errorf("no se pudo firmar el certificado de titularidad: %w", err)
	}

	return SignedAccountOwnershipCertificate{
		Certificate:        certificate,
		SignatureAlgorithm: "RSA-PSS-SHA256",
		Signature:          base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// Comprueba la firma y el formato de un certificado de titularidad.
func VerifyAccountOwnershipCertificate(
	serverPublicKey *rsa.PublicKey,
	signedCertificate SignedAccountOwnershipCertificate,
) error {
	if serverPublicKey == nil {
		return errors.New("la clave pública del servidor no está disponible")
	}
	if signedCertificate.Certificate.Version != accountOwnershipCertificateVersion ||
		signedCertificate.SignatureAlgorithm != "RSA-PSS-SHA256" {
		return errors.New("el formato del certificado de titularidad no es compatible")
	}

	signature, err := base64.StdEncoding.Strict().DecodeString(signedCertificate.Signature)
	if err != nil {
		return errors.New("la firma del certificado no está codificada correctamente")
	}

	digest := sha256.Sum256(accountOwnershipCertificatePayload(signedCertificate.Certificate))
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
		return errors.New("la firma del certificado de titularidad no es válida")
	}

	return nil
}

// Rechaza certificados incompletos o destinados a usuarios sin titularidad.
func validateAccountOwnershipData(data AccountOwnershipData) error {
	if data.HolderID <= 0 ||
		strings.TrimSpace(data.HolderName) == "" ||
		strings.TrimSpace(data.HolderDNI) == "" ||
		data.AccountID <= 0 ||
		strings.TrimSpace(data.IBAN) == "" {
		return errors.New("los datos del certificado de titularidad no son válidos")
	}
	if data.Role != models.AccountRoleOwner && data.Role != models.AccountRoleCoOwner {
		return errors.New("el usuario no es titular de la cuenta")
	}

	return nil
}

// Genera un identificador aleatorio de 128 bits apto para incluirse en una URL.
func randomCertificateID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("no se pudo generar el identificador del certificado: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(value), nil
}

// Construye una representación inequívoca y versionada de los campos firmados.
func accountOwnershipCertificatePayload(certificate AccountOwnershipCertificate) []byte {
	fields := []string{
		accountOwnershipCertificateContext,
		strconv.Itoa(certificate.Version),
		certificate.CertificateID,
		certificate.IssuedAt,
		strconv.FormatInt(certificate.HolderID, 10),
		certificate.HolderName,
		certificate.HolderDNI,
		strconv.FormatInt(certificate.AccountID, 10),
		certificate.IBAN,
		certificate.Role,
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
