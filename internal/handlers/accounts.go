package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"securityBank_server/internal/services"
)

// Cierra una cuenta con saldo cero del usuario autenticado.
func CloseAccount(accountService *services.AccountService) gin.HandlerFunc {
	return func(c *gin.Context) {
		accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || accountID <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Identificador de cuenta inválido",
			})
			return
		}

		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Usuario no autenticado",
			})
			return
		}

		account, err := accountService.CloseAccount(
			c.Request.Context(),
			userID.(int64),
			accountID,
		)
		switch {
		case errors.Is(err, services.ErrAccountNotFound):
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Cuenta no encontrada",
			})
			return
		case errors.Is(err, services.ErrAccountHasBalance):
			c.JSON(http.StatusConflict, gin.H{
				"error": "La cuenta debe tener saldo cero para poder cerrarla",
			})
			return
		case errors.Is(err, services.ErrAccountAlreadyClosed):
			c.JSON(http.StatusConflict, gin.H{
				"error": "La cuenta ya está cerrada",
			})
			return
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudo cerrar la cuenta",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"account": account,
		})
	}
}

// Crea una cuenta nueva para el usuario autenticado.
func CreateAccount(accountService *services.AccountService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Usuario no autenticado",
			})
			return
		}

		account, err := accountService.CreateAccount(
			c.Request.Context(),
			userID.(int64),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudo crear la cuenta",
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"account": account,
		})
	}
}

func FindUserAccounts(accountService *services.AccountService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")

		fmt.Printf("userID=%v, existe=%v\n", userID, exists)

		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Usuario no autenticado",
			})
			return
		}

		accounts, err := accountService.FindUserAccounts(
			c.Request.Context(),
			userID.(int64),
		)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudieron obtener las cuentas",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"accounts": accounts,
		})
	}
}
