package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"securityBank_server/internal/services"
)

type TOTPHandler struct {
	service *services.TOTPService
}

func NewTOTPHandler(service *services.TOTPService) *TOTPHandler {
	return &TOTPHandler{service: service}
}

type TOTPCodeRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

type GenerateTOTPRequest struct {
	Email string `json:"email" binding:"required,email"`
}

func getAuthenticatedUserID(c *gin.Context) (int64, bool) {
	value, exists := c.Get("userID")
	if !exists {
		return 0, false
	}

	userID, ok := value.(int64)
	return userID, ok
}

// Generate permite generar el código QR y secreto para el formulario de registro (público).
func (h *TOTPHandler) Generate(c *gin.Context) {
	var input GenerateTOTPRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Introduce un correo electrónico válido"})
		return
	}

	result, err := h.service.GenerateRegistrationTOTP(input.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar la clave 2FA"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Status devuelve si el usuario autenticado tiene el 2FA activado.
func (h *TOTPHandler) Status(c *gin.Context) {
	userID, ok := getAuthenticatedUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

	enabled, err := h.service.IsTOTPEnabled(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo consultar el estado 2FA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"totp_enabled": enabled,
	})
}

// Setup inicia la configuración 2FA para un usuario autenticado ya existente.
func (h *TOTPHandler) Setup(c *gin.Context) {
	userID, ok := getAuthenticatedUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

	result, err := h.service.SetupTOTP(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, services.ErrTOTPAlreadyEnabled) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo configurar el 2FA"})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (h *TOTPHandler) Enable(c *gin.Context) {
	userID, ok := getAuthenticatedUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

	var request TOTPCodeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Código no válido (debe tener 6 dígitos)"})
		return
	}

	err := h.service.EnableTOTP(
		c.Request.Context(),
		userID,
		request.Code,
	)
	if err != nil {
		if errors.Is(err, services.ErrInvalidTOTP) ||
			errors.Is(err, services.ErrTOTPNotConfigured) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo activar el 2FA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Autenticación de doble factor activada correctamente",
	})
}

func (h *TOTPHandler) Verify(c *gin.Context) {
	userID, ok := getAuthenticatedUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

	var request TOTPCodeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Código no válido (debe tener 6 dígitos)"})
		return
	}

	err := h.service.VerifyTOTP(
		c.Request.Context(),
		userID,
		request.Code,
	)
	if err != nil {
		if errors.Is(err, services.ErrInvalidTOTP) ||
			errors.Is(err, services.ErrTOTPNotConfigured) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Código 2FA incorrecto"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo verificar el 2FA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
	})
}

func (h *TOTPHandler) Disable(c *gin.Context) {
	userID, ok := getAuthenticatedUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

	var request TOTPCodeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Código no válido (debe tener 6 dígitos)"})
		return
	}

	err := h.service.DisableTOTP(
		c.Request.Context(),
		userID,
		request.Code,
	)
	if err != nil {
		if errors.Is(err, services.ErrInvalidTOTP) ||
			errors.Is(err, services.ErrTOTPNotConfigured) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Código 2FA incorrecto"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo desactivar el 2FA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Autenticación de doble factor desactivada",
	})
}
