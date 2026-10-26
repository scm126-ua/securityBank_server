package handlers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"securityBank_server/internal/services"
)

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
