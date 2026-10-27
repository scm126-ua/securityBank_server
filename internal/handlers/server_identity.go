package handlers

import (
	"crypto/rsa"
	"net/http"

	"github.com/gin-gonic/gin"

	"securityBank_server/internal/services"
)

// Entrega la identidad pública necesaria para verificar las firmas del servidor.
func ServerPublicIdentity(serverPrivateKey *rsa.PrivateKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, err := services.ExportServerPublicIdentity(serverPrivateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudo obtener la identidad del servidor",
			})
			return
		}

		c.JSON(http.StatusOK, identity)
	}
}
