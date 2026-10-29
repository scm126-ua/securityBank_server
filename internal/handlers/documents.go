package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"securityBank_server/internal/services"
)

// Tamaño máximo de la petición de subida: 10 MiB cifrados en Base64 (unos
// 13,4 MiB) más los metadatos. Evita agotar la memoria con peticiones enormes.
const maxDocumentUploadRequestSize = 14 << 20

type UploadDocumentRequest struct {
	ID                string `json:"id" binding:"required"`
	Type              string `json:"type" binding:"required"`
	FormatVersion     int16  `json:"format_version" binding:"required"`
	ContentNonce      string `json:"content_nonce" binding:"required"`
	EncryptedContent  string `json:"encrypted_content" binding:"required"`
	MetadataNonce     string `json:"metadata_nonce" binding:"required"`
	EncryptedMetadata string `json:"encrypted_metadata" binding:"required"`
	KeyCommitment     string `json:"key_commitment" binding:"required"`
	KeyAlgorithm      string `json:"key_algorithm" binding:"required"`
	EncryptedKey      string `json:"encrypted_key" binding:"required"`
	Signature         string `json:"signature" binding:"required"`
}

// Lista los documentos accesibles por el usuario autenticado.
func ListDocuments(documentService *services.DocumentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Usuario no autenticado"})
			return
		}

		documents, usage, err := documentService.List(c.Request.Context(), userID.(int64))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudieron obtener los documentos"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"documents": documents,
			"usage":     usage,
		})
	}
}

// Guarda un documento cifrado y firmado en el navegador del usuario.
func UploadDocument(documentService *services.DocumentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Usuario no autenticado"})
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxDocumentUploadRequestSize)

		var input UploadDocumentRequest
		if err := c.ShouldBindJSON(&input); err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{
					"error": "El documento supera el tamaño máximo permitido (10 MB)",
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos del documento inválidos"})
			return
		}

		document, err := documentService.Upload(
			c.Request.Context(),
			userID.(int64),
			services.UploadDocumentInput{
				ID:                input.ID,
				Type:              input.Type,
				FormatVersion:     input.FormatVersion,
				ContentNonce:      input.ContentNonce,
				EncryptedContent:  input.EncryptedContent,
				MetadataNonce:     input.MetadataNonce,
				EncryptedMetadata: input.EncryptedMetadata,
				KeyCommitment:     input.KeyCommitment,
				KeyAlgorithm:      input.KeyAlgorithm,
				EncryptedKey:      input.EncryptedKey,
				Signature:         input.Signature,
			},
		)
		if err != nil {
			respondDocumentError(c, err, "No se pudo guardar el documento")
			return
		}

		c.JSON(http.StatusCreated, gin.H{"document": document})
	}
}

// Entrega el documento cifrado; el cliente lo verifica y lo descifra.
func DownloadDocument(documentService *services.DocumentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Usuario no autenticado"})
			return
		}

		document, err := documentService.Download(c.Request.Context(), userID.(int64), c.Param("id"))
		if err != nil {
			respondDocumentError(c, err, "No se pudo obtener el documento")
			return
		}

		c.JSON(http.StatusOK, gin.H{"document": document})
	}
}

// Elimina un documento del que el usuario autenticado es propietario.
func DeleteDocument(documentService *services.DocumentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Usuario no autenticado"})
			return
		}

		if err := documentService.Delete(c.Request.Context(), userID.(int64), c.Param("id")); err != nil {
			respondDocumentError(c, err, "No se pudo eliminar el documento")
			return
		}

		c.Status(http.StatusNoContent)
	}
}

// Traduce los errores del servicio a respuestas sin detalles internos.
func respondDocumentError(c *gin.Context, err error, fallback string) {
	switch {
	case errors.Is(err, services.ErrInvalidDocumentID):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Identificador de documento inválido"})
	case errors.Is(err, services.ErrInvalidDocument):
		c.JSON(http.StatusBadRequest, gin.H{"error": "El documento cifrado no tiene un formato válido"})
	case errors.Is(err, services.ErrInvalidDocumentSignature):
		c.JSON(http.StatusBadRequest, gin.H{"error": "La firma del documento no es válida"})
	case errors.Is(err, services.ErrDocumentNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Documento no encontrado"})
	case errors.Is(err, services.ErrDocumentNotOwner):
		c.JSON(http.StatusForbidden, gin.H{"error": "Solo el propietario puede eliminar el documento"})
	case errors.Is(err, services.ErrDocumentQuotaExceeded):
		c.JSON(http.StatusConflict, gin.H{"error": "Has alcanzado el límite de almacenamiento de documentos"})
	case errors.Is(err, services.ErrDocumentAlreadyExists):
		c.JSON(http.StatusConflict, gin.H{"error": "Ya existe un documento con ese identificador"})
	case errors.Is(err, services.ErrKeyMaterialUnavailable):
		c.JSON(http.StatusConflict, gin.H{"error": "El usuario no tiene claves criptográficas"})
	case errors.Is(err, services.ErrDocumentIntegrity):
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "La integridad del documento no se ha podido verificar: no se entrega",
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": fallback})
	}
}
