package services

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"regexp"
	"strconv"

	"securityBank_server/internal/models"
)

const (
	DocumentFormatVersion = 1
	// Tamaño máximo del documento original. Padmé no lo aumenta porque es múltiplo de 256 KiB.
	MaxDocumentSize = 10 * 1024 * 1024
	// Los documentos pequeños se rellenan hasta este tamaño para no revelar su longitud.
	minPaddedDocumentSize = 1024
	// Los metadatos se rellenan siempre a este tamaño antes de cifrarlos.
	documentMetadataPaddedSize = 2048
	documentKeyCommitmentSize  = 32
	rsa3072Size                = 3072 / 8
	documentManifestContext    = "securitybank-document-manifest-v1"
	documentSignatureAlgorithm = "RSA-PSS-SHA256"
)

var (
	ErrInvalidDocument          = errors.New("documento cifrado no válido")
	ErrInvalidDocumentID        = errors.New("identificador de documento no válido")
	ErrInvalidDocumentSignature = errors.New("firma del documento no válida")
	ErrDocumentIntegrity        = errors.New("la integridad del documento no se puede verificar")
)

// UUID v4 en minúsculas: la misma forma que devuelve PostgreSQL y que el cliente autentica.
var documentPublicIDPattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

// Tipos que un usuario puede subir. STATEMENT y TRANSACTION_RECEIPT se reservan
// para documentos que generará y firmará el propio banco.
var uploadableDocumentTypes = map[string]bool{
	models.DocumentTypePersonal:             true,
	models.DocumentTypeOwnershipCertificate: true,
}

// Datos de subida tal como llegan del cliente, codificados en Base64.
type UploadDocumentInput struct {
	ID                string
	Type              string
	FormatVersion     int16
	ContentNonce      string
	EncryptedContent  string
	MetadataNonce     string
	EncryptedMetadata string
	KeyCommitment     string
	KeyAlgorithm      string
	EncryptedKey      string
	Signature         string
}

type validatedDocumentUpload struct {
	publicID          string
	documentType      string
	contentNonce      []byte
	encryptedContent  []byte
	metadataNonce     []byte
	encryptedMetadata []byte
	keyCommitment     []byte
	encryptedKey      []byte
	signature         []byte
}

// Campos que firma el propietario: identifican el documento cifrado de forma inequívoca.
type documentManifestFields struct {
	publicID          string
	ownerID           int64
	documentType      string
	formatVersion     int16
	contentNonce      []byte
	encryptedContent  []byte
	metadataNonce     []byte
	encryptedMetadata []byte
	keyCommitment     []byte
}

// Indica si el valor tiene el formato de identificador público de documento.
func IsDocumentPublicID(value string) bool {
	return documentPublicIDPattern.MatchString(value)
}

// Comprueba la estructura del documento cifrado sin poder ver su contenido.
func validateDocumentUpload(input UploadDocumentInput) (*validatedDocumentUpload, error) {
	if !IsDocumentPublicID(input.ID) {
		return nil, fmt.Errorf("%w: identificador incorrecto", ErrInvalidDocument)
	}
	if !uploadableDocumentTypes[input.Type] {
		return nil, fmt.Errorf("%w: tipo de documento no permitido", ErrInvalidDocument)
	}
	if input.FormatVersion != DocumentFormatVersion {
		return nil, fmt.Errorf("%w: versión de formato no compatible", ErrInvalidDocument)
	}
	if input.KeyAlgorithm != models.DocumentKeyAlgorithmRSAOAEP3072 {
		return nil, fmt.Errorf("%w: algoritmo de protección de clave no compatible", ErrInvalidDocument)
	}

	document := &validatedDocumentUpload{
		publicID:     input.ID,
		documentType: input.Type,
	}

	fields := []struct {
		name   string
		value  string
		target *[]byte
		valid  func(size int) bool
	}{
		{"nonce del contenido", input.ContentNonce, &document.contentNonce, exactSize(models.GCMNonceSize)},
		{"contenido cifrado", input.EncryptedContent, &document.encryptedContent, func(size int) bool {
			return isPaddedDocumentSize(size - models.GCMTagSize)
		}},
		{"nonce de los metadatos", input.MetadataNonce, &document.metadataNonce, exactSize(models.GCMNonceSize)},
		{"metadatos cifrados", input.EncryptedMetadata, &document.encryptedMetadata, exactSize(documentMetadataPaddedSize + models.GCMTagSize)},
		{"compromiso de clave", input.KeyCommitment, &document.keyCommitment, exactSize(documentKeyCommitmentSize)},
		// La clave envuelta y la firma ocupan lo mismo que el módulo RSA-3072 del usuario.
		{"clave envuelta", input.EncryptedKey, &document.encryptedKey, exactSize(rsa3072Size)},
		{"firma", input.Signature, &document.signature, exactSize(rsa3072Size)},
	}

	for _, field := range fields {
		decoded, err := decodeBase64(field.value)
		if err != nil || !field.valid(len(decoded)) {
			return nil, fmt.Errorf("%w: %s incorrecto", ErrInvalidDocument, field.name)
		}
		*field.target = decoded
	}

	// Reutilizar un nonce con la misma clave rompe la confidencialidad y la integridad de AES-GCM.
	if bytes.Equal(document.contentNonce, document.metadataNonce) {
		return nil, fmt.Errorf("%w: los nonces deben ser distintos", ErrInvalidDocument)
	}

	return document, nil
}

// Devuelve un validador de longitud exacta.
func exactSize(expected int) func(size int) bool {
	return func(size int) bool {
		return size == expected
	}
}

// Comprueba que el contenido rellenado tiene un tamaño Padmé permitido.
func isPaddedDocumentSize(size int) bool {
	return size >= minPaddedDocumentSize &&
		size <= MaxDocumentSize &&
		padmeLength(size) == size
}

// Calcula el tamaño Padmé: redondea dejando visibles solo O(log log L) bits de la longitud.
// Referencia: Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and
// Communication with PURBs" (PETS 2019).
func padmeLength(length int) int {
	if length < 2 {
		return length
	}

	exponent := bits.Len(uint(length)) - 1
	exponentBits := bits.Len(uint(exponent))
	lastBits := exponent - exponentBits
	mask := (1 << lastBits) - 1

	return (length + mask) &^ mask
}

// Construye el manifiesto firmado por el propietario del documento.
func documentManifest(fields documentManifestFields) []byte {
	contentDigest := sha256.Sum256(fields.encryptedContent)
	metadataDigest := sha256.Sum256(fields.encryptedMetadata)

	return lengthPrefixedPayload(
		documentManifestContext,
		fields.publicID,
		strconv.FormatInt(fields.ownerID, 10),
		fields.documentType,
		strconv.Itoa(int(fields.formatVersion)),
		base64.StdEncoding.EncodeToString(fields.contentNonce),
		hex.EncodeToString(contentDigest[:]),
		base64.StdEncoding.EncodeToString(fields.metadataNonce),
		hex.EncodeToString(metadataDigest[:]),
		hex.EncodeToString(fields.keyCommitment),
	)
}

// Codifica cada campo precedido de su longitud para que la representación sea inequívoca.
func lengthPrefixedPayload(fields ...string) []byte {
	payload := make([]byte, 0)
	for _, field := range fields {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(field)))
		payload = append(payload, field...)
	}

	return payload
}
