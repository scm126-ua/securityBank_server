package repositories

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"securityBank_server/internal/models"
)

var (
	ErrDocumentNotFound      = errors.New("documento no encontrado")
	ErrDocumentNotOwner      = errors.New("el usuario no es propietario del documento")
	ErrDocumentQuotaExceeded = errors.New("límite de almacenamiento de documentos superado")
	ErrDocumentAlreadyExists = errors.New("ya existe un documento con ese identificador")
)

// Límites de almacenamiento de cada usuario. MaxBytes cuenta el tamaño cifrado.
type DocumentQuota struct {
	MaxDocuments int64
	MaxBytes     int64
}

// Almacenamiento ocupado por los documentos de los que el usuario es propietario.
type DocumentUsage struct {
	Documents int64 `gorm:"column:documents"`
	Bytes     int64 `gorm:"column:bytes"`
}

// Documento accesible por el usuario, sin el contenido cifrado.
type DocumentListRecord struct {
	PublicID          string    `gorm:"column:public_id"`
	OwnerID           int64     `gorm:"column:owner_id"`
	Type              string    `gorm:"column:type"`
	FormatVersion     int16     `gorm:"column:format_version"`
	CiphertextSize    int64     `gorm:"column:ciphertext_size"`
	EncryptedMetadata []byte    `gorm:"column:encrypted_metadata"`
	MetadataNonce     []byte    `gorm:"column:metadata_nonce"`
	KeyCommitment     []byte    `gorm:"column:key_commitment"`
	CreatedAt         time.Time `gorm:"column:created_at"`
	EncryptedKey      []byte    `gorm:"column:encrypted_key"`
	KeyAlgorithm      string    `gorm:"column:key_algorithm"`
	Permission        string    `gorm:"column:permission"`
}

// Documento completo junto con la identidad pública de su propietario.
type DocumentRecord struct {
	DocumentListRecord
	EncryptedContent         []byte  `gorm:"column:encrypted_content"`
	ContentNonce             []byte  `gorm:"column:content_nonce"`
	Signature                []byte  `gorm:"column:signature"`
	OwnerEmail               string  `gorm:"column:owner_email"`
	OwnerPublicKey           *string `gorm:"column:owner_public_key"`
	OwnerSigningPublicKey    *string `gorm:"column:owner_signing_public_key"`
	OwnerPublicKeysSignature *string `gorm:"column:owner_public_keys_signature"`
}

type documentGrant struct {
	DocumentID int64  `gorm:"column:document_id"`
	Permission string `gorm:"column:permission"`
}

// Columnas del listado: tamaño cifrado en lugar del contenido para no cargarlo.
const documentSummaryColumns = `
	documents.public_id AS public_id,
	documents.owner_id AS owner_id,
	documents.type AS type,
	documents.format_version AS format_version,
	octet_length(documents.encrypted_content) AS ciphertext_size,
	documents.encrypted_metadata AS encrypted_metadata,
	documents.metadata_nonce AS metadata_nonce,
	documents.key_commitment AS key_commitment,
	documents.created_at AS created_at,
	document_access.encrypted_aes_key AS encrypted_key,
	document_access.key_algorithm AS key_algorithm,
	document_access.permission AS permission`

type DocumentRepository struct {
	db    *gorm.DB
	quota DocumentQuota
}

func NewDocumentRepository(db *gorm.DB, quota DocumentQuota) *DocumentRepository {
	return &DocumentRepository{db: db, quota: quota}
}

// Devuelve los límites de almacenamiento aplicados a cada usuario.
func (r *DocumentRepository) Quota() DocumentQuota {
	return r.quota
}

// Limita cualquier consulta a los documentos con un acceso vigente del usuario.
func accessibleDocuments(tx *gorm.DB, userID int64) *gorm.DB {
	return tx.Table("document_access").
		Joins("JOIN documents ON documents.id = document_access.document_id").
		Where("document_access.user_id = ?", userID).
		Where("document_access.revoked = ?", false)
}

// Lista los documentos propios y, en el futuro, los compartidos con el usuario.
func (r *DocumentRepository) ListForUser(
	ctx context.Context,
	userID int64,
) ([]DocumentListRecord, error) {
	records := make([]DocumentListRecord, 0)

	err := accessibleDocuments(r.db.WithContext(ctx), userID).
		Select(documentSummaryColumns).
		Order("documents.created_at DESC, documents.id DESC").
		Scan(&records).Error
	if err != nil {
		return nil, err
	}

	return records, nil
}

// Obtiene un documento solo si el usuario tiene un acceso vigente. Si no lo
// tiene, responde igual que si no existiera para no revelar su existencia.
func (r *DocumentRepository) FindForUser(
	ctx context.Context,
	userID int64,
	publicID string,
) (*DocumentRecord, error) {
	var record DocumentRecord

	err := accessibleDocuments(r.db.WithContext(ctx), userID).
		Joins("JOIN users AS owners ON owners.id = documents.owner_id").
		Select(documentSummaryColumns+`,
			documents.encrypted_content AS encrypted_content,
			documents.nonce AS content_nonce,
			documents.signature AS signature,
			owners.email AS owner_email,
			owners.public_key AS owner_public_key,
			owners.signing_public_key AS owner_signing_public_key,
			owners.public_keys_signature AS owner_public_keys_signature`).
		Where("documents.public_id = ?", publicID).
		Take(&record).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDocumentNotFound
	}
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// Calcula el almacenamiento ocupado por el usuario.
func (r *DocumentRepository) Usage(
	ctx context.Context,
	ownerID int64,
) (DocumentUsage, error) {
	return documentUsage(r.db.WithContext(ctx), ownerID)
}

// Guarda el documento, la clave envuelta del propietario y su auditoría en una
// única transacción, respetando la cuota del usuario.
func (r *DocumentRepository) Create(
	ctx context.Context,
	document *models.Document,
	ownerAccess *models.DocumentAccess,
) error {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Bloquea al usuario para que dos subidas simultáneas no superen la cuota.
		var owner models.User
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id").
			First(&owner, document.OwnerID).Error
		if err != nil {
			return err
		}

		usage, err := documentUsage(tx, document.OwnerID)
		if err != nil {
			return err
		}
		if usage.Documents+1 > r.quota.MaxDocuments ||
			usage.Bytes+int64(len(document.EncryptedContent)) > r.quota.MaxBytes {
			return ErrDocumentQuotaExceeded
		}

		var existing int64
		err = tx.Model(&models.Document{}).
			Where("public_id = ?", document.PublicID).
			Count(&existing).Error
		if err != nil {
			return err
		}
		if existing > 0 {
			return ErrDocumentAlreadyExists
		}

		if err := tx.Create(document).Error; err != nil {
			return err
		}

		ownerAccess.DocumentID = document.ID
		if err := tx.Create(ownerAccess).Error; err != nil {
			return err
		}

		return createDocumentAuditEvent(tx, &models.DocumentAuditEvent{
			UserID:     document.OwnerID,
			DocumentID: &document.PublicID,
			Action:     models.DocumentAuditActionUpload,
			Result:     models.DocumentAuditResultSuccess,
		})
	})

	if err != nil {
		return r.auditDenial(ctx, document.OwnerID, document.PublicID, models.DocumentAuditActionUpload, err)
	}

	return nil
}

// Elimina un documento del que el usuario es propietario. ON DELETE CASCADE
// borra también todas las copias envueltas de su clave AES.
func (r *DocumentRepository) Delete(
	ctx context.Context,
	userID int64,
	publicID string,
) error {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var grant documentGrant
		err := accessibleDocuments(tx, userID).
			Select("document_access.document_id AS document_id, document_access.permission AS permission").
			Where("documents.public_id = ?", publicID).
			Take(&grant).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrDocumentNotFound
		}
		if err != nil {
			return err
		}
		if grant.Permission != models.DocumentPermissionOwner {
			return ErrDocumentNotOwner
		}

		result := tx.Where("id = ?", grant.DocumentID).Delete(&models.Document{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrDocumentNotFound
		}

		return createDocumentAuditEvent(tx, &models.DocumentAuditEvent{
			UserID:     userID,
			DocumentID: &publicID,
			Action:     models.DocumentAuditActionDelete,
			Result:     models.DocumentAuditResultSuccess,
		})
	})

	if err != nil {
		return r.auditDenial(ctx, userID, publicID, models.DocumentAuditActionDelete, err)
	}

	return nil
}

// Registra un evento de auditoría fuera de una operación transaccional.
func (r *DocumentRepository) RecordAuditEvent(
	ctx context.Context,
	event *models.DocumentAuditEvent,
) error {
	return createDocumentAuditEvent(r.db.WithContext(ctx), event)
}

// Audita los rechazos esperados después de que la transacción principal haya terminado.
func (r *DocumentRepository) auditDenial(
	ctx context.Context,
	userID int64,
	publicID string,
	action string,
	err error,
) error {
	reason, shouldAudit := documentDenialReason(err)
	if !shouldAudit {
		return err
	}

	auditErr := r.RecordAuditEvent(ctx, &models.DocumentAuditEvent{
		UserID:     userID,
		DocumentID: &publicID,
		Action:     action,
		Result:     models.DocumentAuditResultDenied,
		Reason:     &reason,
	})
	if auditErr != nil {
		return errors.Join(err, auditErr)
	}

	return err
}

// Traduce los rechazos esperados a códigos de auditoría sin datos sensibles.
func documentDenialReason(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrDocumentNotFound):
		return models.DocumentAuditReasonNotFound, true
	case errors.Is(err, ErrDocumentNotOwner):
		return models.DocumentAuditReasonNotOwner, true
	case errors.Is(err, ErrDocumentQuotaExceeded):
		return models.DocumentAuditReasonQuotaExceeded, true
	case errors.Is(err, ErrDocumentAlreadyExists):
		return models.DocumentAuditReasonDuplicateID, true
	default:
		return "", false
	}
}

// Suma los documentos y bytes cifrados que pertenecen al usuario.
func documentUsage(tx *gorm.DB, ownerID int64) (DocumentUsage, error) {
	var usage DocumentUsage

	err := tx.Model(&models.Document{}).
		Select("COUNT(*) AS documents, COALESCE(SUM(octet_length(encrypted_content)), 0) AS bytes").
		Where("owner_id = ?", ownerID).
		Scan(&usage).Error

	return usage, err
}

// Inserta un evento de auditoría de documentos con la conexión o transacción recibida.
func createDocumentAuditEvent(tx *gorm.DB, event *models.DocumentAuditEvent) error {
	return tx.Create(event).Error
}
