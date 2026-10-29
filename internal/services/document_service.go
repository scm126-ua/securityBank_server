// Gestiona el almacenamiento de documentos cifrados de extremo a extremo.
//
// El servidor nunca recibe claves AES ni datos en claro: valida el formato,
// comprueba la firma del propietario, aplica el control de acceso y audita.

package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"time"

	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
)

var (
	ErrDocumentNotFound      = repositories.ErrDocumentNotFound
	ErrDocumentNotOwner      = repositories.ErrDocumentNotOwner
	ErrDocumentQuotaExceeded = repositories.ErrDocumentQuotaExceeded
	ErrDocumentAlreadyExists = repositories.ErrDocumentAlreadyExists
)

// Límites por usuario: 100 documentos y 100 MiB cifrados.
var DefaultDocumentQuota = repositories.DocumentQuota{
	MaxDocuments: 100,
	MaxBytes:     100 * 1024 * 1024,
}

// Datos de un documento necesarios para descifrar sus metadatos en el cliente.
type DocumentSummary struct {
	ID                string    `json:"id"`
	OwnerID           int64     `json:"owner_id"`
	Type              string    `json:"type"`
	FormatVersion     int16     `json:"format_version"`
	Permission        string    `json:"permission"`
	CiphertextSize    int64     `json:"ciphertext_size"`
	CreatedAt         time.Time `json:"created_at"`
	MetadataNonce     []byte    `json:"metadata_nonce"`
	EncryptedMetadata []byte    `json:"encrypted_metadata"`
	KeyCommitment     []byte    `json:"key_commitment"`
	KeyAlgorithm      string    `json:"key_algorithm"`
	EncryptedKey      []byte    `json:"encrypted_key"`
}

// Identidad pública del propietario, certificada por el servidor.
type DocumentOwner struct {
	ID                  int64  `json:"id"`
	Email               string `json:"email"`
	PublicKey           string `json:"public_key"`
	SigningPublicKey    string `json:"signing_public_key"`
	PublicKeysSignature string `json:"public_keys_signature"`
}

// Documento cifrado completo con todo lo necesario para verificarlo en el cliente.
type DocumentDownload struct {
	DocumentSummary
	ContentNonce       []byte        `json:"content_nonce"`
	EncryptedContent   []byte        `json:"encrypted_content"`
	Signature          []byte        `json:"signature"`
	SignatureAlgorithm string        `json:"signature_algorithm"`
	Owner              DocumentOwner `json:"owner"`
}

// Almacenamiento ocupado y disponible del usuario.
type DocumentStorageUsage struct {
	Documents    int64 `json:"documents"`
	MaxDocuments int64 `json:"max_documents"`
	UsedBytes    int64 `json:"used_bytes"`
	MaxBytes     int64 `json:"max_bytes"`
}

type DocumentService struct {
	documents       *repositories.DocumentRepository
	users           *repositories.UserRepository
	serverPublicKey *rsa.PublicKey
}

func NewDocumentService(
	documents *repositories.DocumentRepository,
	users *repositories.UserRepository,
	serverPublicKey *rsa.PublicKey,
) *DocumentService {
	return &DocumentService{
		documents:       documents,
		users:           users,
		serverPublicKey: serverPublicKey,
	}
}

// Valida y guarda un documento cifrado y firmado por el usuario autenticado.
func (s *DocumentService) Upload(
	ctx context.Context,
	userID int64,
	input UploadDocumentInput,
) (*DocumentSummary, error) {
	upload, err := validateDocumentUpload(input)
	if err != nil {
		return nil, err
	}

	owner, err := s.certifiedUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	document := &models.Document{
		PublicID:          upload.publicID,
		OwnerID:           userID,
		Type:              upload.documentType,
		FormatVersion:     DocumentFormatVersion,
		EncryptedContent:  upload.encryptedContent,
		Nonce:             upload.contentNonce,
		EncryptedMetadata: upload.encryptedMetadata,
		MetadataNonce:     upload.metadataNonce,
		KeyCommitment:     upload.keyCommitment,
		Signature:         upload.signature,
	}

	// La firma prueba que el documento cifrado procede del usuario y no se ha alterado por el camino.
	manifest := documentManifest(manifestFieldsForDocument(document))
	if err := verifyUserSignature(*owner.SigningPublicKey, manifest, upload.signature); err != nil {
		auditErr := s.recordAudit(
			ctx, userID, upload.publicID,
			models.DocumentAuditActionUpload,
			models.DocumentAuditResultDenied,
			models.DocumentAuditReasonInvalidSignature,
		)
		return nil, errors.Join(ErrInvalidDocumentSignature, auditErr)
	}

	access := &models.DocumentAccess{
		UserID:          userID,
		EncryptedAESKey: upload.encryptedKey,
		KeyAlgorithm:    models.DocumentKeyAlgorithmRSAOAEP3072,
		Permission:      models.DocumentPermissionOwner,
		GrantedBy:       userID,
	}
	if err := s.documents.Create(ctx, document, access); err != nil {
		return nil, err
	}

	return &DocumentSummary{
		ID:                document.PublicID,
		OwnerID:           document.OwnerID,
		Type:              document.Type,
		FormatVersion:     document.FormatVersion,
		Permission:        access.Permission,
		CiphertextSize:    int64(len(document.EncryptedContent)),
		CreatedAt:         document.CreatedAt,
		MetadataNonce:     document.MetadataNonce,
		EncryptedMetadata: document.EncryptedMetadata,
		KeyCommitment:     document.KeyCommitment,
		KeyAlgorithm:      access.KeyAlgorithm,
		EncryptedKey:      access.EncryptedAESKey,
	}, nil
}

// Lista los documentos accesibles y el almacenamiento ocupado por el usuario.
func (s *DocumentService) List(
	ctx context.Context,
	userID int64,
) ([]DocumentSummary, DocumentStorageUsage, error) {
	records, err := s.documents.ListForUser(ctx, userID)
	if err != nil {
		return nil, DocumentStorageUsage{}, err
	}

	usage, err := s.documents.Usage(ctx, userID)
	if err != nil {
		return nil, DocumentStorageUsage{}, err
	}

	summaries := make([]DocumentSummary, 0, len(records))
	for _, record := range records {
		summaries = append(summaries, summaryFromRecord(record))
	}

	quota := s.documents.Quota()
	return summaries, DocumentStorageUsage{
		Documents:    usage.Documents,
		MaxDocuments: quota.MaxDocuments,
		UsedBytes:    usage.Bytes,
		MaxBytes:     quota.MaxBytes,
	}, nil
}

// Entrega un documento cifrado después de comprobar el acceso y su integridad.
// Si la descarga no puede auditarse, no se entrega.
func (s *DocumentService) Download(
	ctx context.Context,
	userID int64,
	publicID string,
) (*DocumentDownload, error) {
	if !IsDocumentPublicID(publicID) {
		return nil, ErrInvalidDocumentID
	}

	record, err := s.documents.FindForUser(ctx, userID, publicID)
	if errors.Is(err, ErrDocumentNotFound) {
		auditErr := s.recordAudit(
			ctx, userID, publicID,
			models.DocumentAuditActionDownload,
			models.DocumentAuditResultDenied,
			models.DocumentAuditReasonNotFound,
		)
		return nil, errors.Join(err, auditErr)
	}
	if err != nil {
		return nil, err
	}

	owner, err := s.verifyStoredDocument(record)
	if err != nil {
		auditErr := s.recordAudit(
			ctx, userID, publicID,
			models.DocumentAuditActionDownload,
			models.DocumentAuditResultError,
			models.DocumentAuditReasonIntegrityFailure,
		)
		return nil, errors.Join(ErrDocumentIntegrity, auditErr)
	}

	err = s.recordAudit(
		ctx, userID, publicID,
		models.DocumentAuditActionDownload,
		models.DocumentAuditResultSuccess,
		"",
	)
	if err != nil {
		return nil, err
	}

	return &DocumentDownload{
		DocumentSummary:    summaryFromRecord(record.DocumentListRecord),
		ContentNonce:       record.ContentNonce,
		EncryptedContent:   record.EncryptedContent,
		Signature:          record.Signature,
		SignatureAlgorithm: documentSignatureAlgorithm,
		Owner:              owner,
	}, nil
}

// Elimina un documento si el usuario autenticado es su propietario.
func (s *DocumentService) Delete(
	ctx context.Context,
	userID int64,
	publicID string,
) error {
	if !IsDocumentPublicID(publicID) {
		return ErrInvalidDocumentID
	}

	return s.documents.Delete(ctx, userID, publicID)
}

// Carga al usuario y comprueba que sus claves públicas siguen certificadas por el servidor.
func (s *DocumentService) certifiedUser(
	ctx context.Context,
	userID int64,
) (*models.User, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.PublicKey == nil ||
		user.SigningPublicKey == nil ||
		user.PublicKeysSignature == nil {
		return nil, ErrKeyMaterialUnavailable
	}

	if err := VerifyUserPublicKeys(
		s.serverPublicKey,
		user.Email,
		*user.PublicKey,
		*user.SigningPublicKey,
		*user.PublicKeysSignature,
	); err != nil {
		return nil, ErrInvalidKeyCertificate
	}

	return user, nil
}

// Comprueba el certificado del propietario y su firma sobre el documento almacenado.
// Detecta manipulaciones de los datos en reposo (por ejemplo, en la base de datos).
func (s *DocumentService) verifyStoredDocument(
	record *repositories.DocumentRecord,
) (DocumentOwner, error) {
	if record.FormatVersion != DocumentFormatVersion ||
		record.OwnerPublicKey == nil ||
		record.OwnerSigningPublicKey == nil ||
		record.OwnerPublicKeysSignature == nil {
		return DocumentOwner{}, ErrDocumentIntegrity
	}

	if err := VerifyUserPublicKeys(
		s.serverPublicKey,
		record.OwnerEmail,
		*record.OwnerPublicKey,
		*record.OwnerSigningPublicKey,
		*record.OwnerPublicKeysSignature,
	); err != nil {
		return DocumentOwner{}, ErrDocumentIntegrity
	}

	manifest := documentManifest(documentManifestFields{
		publicID:          record.PublicID,
		ownerID:           record.OwnerID,
		documentType:      record.Type,
		formatVersion:     record.FormatVersion,
		contentNonce:      record.ContentNonce,
		encryptedContent:  record.EncryptedContent,
		metadataNonce:     record.MetadataNonce,
		encryptedMetadata: record.EncryptedMetadata,
		keyCommitment:     record.KeyCommitment,
	})
	if err := verifyUserSignature(*record.OwnerSigningPublicKey, manifest, record.Signature); err != nil {
		return DocumentOwner{}, ErrDocumentIntegrity
	}

	return DocumentOwner{
		ID:                  record.OwnerID,
		Email:               record.OwnerEmail,
		PublicKey:           *record.OwnerPublicKey,
		SigningPublicKey:    *record.OwnerSigningPublicKey,
		PublicKeysSignature: *record.OwnerPublicKeysSignature,
	}, nil
}

// Registra un evento de auditoría; reason vacío significa éxito.
func (s *DocumentService) recordAudit(
	ctx context.Context,
	userID int64,
	publicID string,
	action string,
	result string,
	reason string,
) error {
	event := &models.DocumentAuditEvent{
		UserID:     userID,
		DocumentID: &publicID,
		Action:     action,
		Result:     result,
	}
	if reason != "" {
		event.Reason = &reason
	}

	return s.documents.RecordAuditEvent(ctx, event)
}

// Obtiene los campos firmados de un documento.
func manifestFieldsForDocument(document *models.Document) documentManifestFields {
	return documentManifestFields{
		publicID:          document.PublicID,
		ownerID:           document.OwnerID,
		documentType:      document.Type,
		formatVersion:     document.FormatVersion,
		contentNonce:      document.Nonce,
		encryptedContent:  document.EncryptedContent,
		metadataNonce:     document.MetadataNonce,
		encryptedMetadata: document.EncryptedMetadata,
		keyCommitment:     document.KeyCommitment,
	}
}

// Convierte un registro del repositorio en la respuesta de la API.
func summaryFromRecord(record repositories.DocumentListRecord) DocumentSummary {
	return DocumentSummary{
		ID:                record.PublicID,
		OwnerID:           record.OwnerID,
		Type:              record.Type,
		FormatVersion:     record.FormatVersion,
		Permission:        record.Permission,
		CiphertextSize:    record.CiphertextSize,
		CreatedAt:         record.CreatedAt,
		MetadataNonce:     record.MetadataNonce,
		EncryptedMetadata: record.EncryptedMetadata,
		KeyCommitment:     record.KeyCommitment,
		KeyAlgorithm:      record.KeyAlgorithm,
		EncryptedKey:      record.EncryptedKey,
	}
}
