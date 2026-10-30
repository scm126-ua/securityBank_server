package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/shopspring/decimal"

	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
	"securityBank_server/internal/services"
)

// ─── Estructuras de Petición ──────────────────────────────────────────────────

type DepositRequest struct {
	Amount         decimal.Decimal `json:"amount" binding:"required"`
	Description    string          `json:"description"`
	IdempotencyKey string          `json:"idempotency_key"`
}

type WithdrawRequest struct {
	Amount         decimal.Decimal `json:"amount" binding:"required"`
	Description    string          `json:"description"`
	IdempotencyKey string          `json:"idempotency_key"`
}

type TransferRequest struct {
	DestinationIBAN string          `json:"destination_iban" binding:"required"`
	Amount          decimal.Decimal `json:"amount" binding:"required"`
	Description     string          `json:"description"`
	IdempotencyKey  string          `json:"idempotency_key"`
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// Deposit permite ingresar fondos en una cuenta bancaria activa del usuario.
func Deposit(txService services.TransactionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			return
		}

		accountID, ok := parseAccountID(c)
		if !ok {
			return
		}

		var req DepositRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos del ingreso inválidos"})
			return
		}

		if req.Amount.LessThanOrEqual(decimal.Zero) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "El importe debe ser mayor que cero"})
			return
		}

		idempKey := resolveIdempotencyKey(c, req.IdempotencyKey)

		tx, err := txService.Deposit(c.Request.Context(), userID, accountID, req.Amount, req.Description, idempKey)
		if err != nil {
			handleTransactionError(c, err, "No se pudo realizar el ingreso")
			return
		}

		c.JSON(http.StatusOK, tx)
	}
}

// Withdraw permite retirar fondos de una cuenta si dispone de saldo suficiente.
func Withdraw(txService services.TransactionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			return
		}

		accountID, ok := parseAccountID(c)
		if !ok {
			return
		}

		var req WithdrawRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos de la retirada inválidos"})
			return
		}

		if req.Amount.LessThanOrEqual(decimal.Zero) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "El importe debe ser mayor que cero"})
			return
		}

		idempKey := resolveIdempotencyKey(c, req.IdempotencyKey)

		tx, err := txService.Withdraw(c.Request.Context(), userID, accountID, req.Amount, req.Description, idempKey)
		if err != nil {
			handleTransactionError(c, err, "No se pudo realizar la retirada")
			return
		}

		c.JSON(http.StatusOK, tx)
	}
}

// Transfer envía fondos desde la cuenta del usuario a otra cuenta mediante su IBAN.
func Transfer(txService services.TransactionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			return
		}

		sourceAccountID, ok := parseAccountID(c)
		if !ok {
			return
		}

		var req TransferRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos de la transferencia inválidos"})
			return
		}

		destIBAN := strings.ToUpper(strings.ReplaceAll(req.DestinationIBAN, " ", ""))
		if destIBAN == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "El IBAN de destino es obligatorio"})
			return
		}

		if req.Amount.LessThanOrEqual(decimal.Zero) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "El importe debe ser mayor que cero"})
			return
		}

		idempKey := resolveIdempotencyKey(c, req.IdempotencyKey)

		tx, err := txService.Transfer(c.Request.Context(), userID, sourceAccountID, destIBAN, req.Amount, req.Description, idempKey)
		if err != nil {
			handleTransactionError(c, err, "No se pudo realizar la transferencia")
			return
		}

		c.JSON(http.StatusOK, tx)
	}
}

// ListTransactions lista los movimientos de una cuenta de forma paginada y filtrada.
func ListTransactions(txService services.TransactionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			return
		}

		accountID, ok := parseAccountID(c)
		if !ok {
			return
		}

		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		txType := strings.ToUpper(strings.TrimSpace(c.Query("type")))

		filter := repositories.TransactionFilter{
			Type: txType,
		}

		txs, total, err := txService.ListTransactions(c.Request.Context(), userID, accountID, filter, page, pageSize)
		if err != nil {
			handleTransactionError(c, err, "No se pudieron obtener los movimientos")
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"transactions": txs,
			"total":        total,
			"page":         page,
			"page_size":    pageSize,
		})
	}
}

// GetTransactionReceipt devuelve un justificante oficial firmado con RSA-PSS.
func GetTransactionReceipt(txService services.TransactionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			return
		}

		reference := strings.TrimSpace(c.Param("reference"))
		if reference == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Referencia de transacción no proporcionada"})
			return
		}

		receipt, err := txService.GenerateReceipt(c.Request.Context(), userID, reference)
		if err != nil {
			switch {
			case errors.Is(err, repositories.ErrUnauthorized):
				c.JSON(http.StatusForbidden, gin.H{"error": "No tienes permiso para ver esta transacción"})
			case errors.Is(err, repositories.ErrAccountNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "Transacción no encontrada"})
			case errors.Is(err, services.ErrTamperedTransaction):
				c.JSON(http.StatusConflict, gin.H{"error": "Alerta de seguridad: la integridad del movimiento no pudo ser verificada"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar el justificante"})
			}
			return
		}

		c.JSON(http.StatusOK, receipt)
	}
}

// GetAccountStatement genera un extracto bancario consolidado con totales y movimientos,
// firmado digitalmente con RSA-PSS por el banco.
func GetAccountStatement(txService services.TransactionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			return
		}

		accountID, ok := parseAccountID(c)
		if !ok {
			return
		}

		statement, err := txService.GenerateStatement(c.Request.Context(), userID, accountID)
		if err != nil {
			switch {
			case errors.Is(err, repositories.ErrUnauthorized):
				c.JSON(http.StatusForbidden, gin.H{"error": "No estás autorizado para obtener el extracto de esta cuenta"})
			case errors.Is(err, repositories.ErrAccountNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "Cuenta no encontrada"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar el extracto bancario"})
			}
			return
		}

		c.JSON(http.StatusOK, statement)
	}
}

// ─── Utilidades auxiliares ────────────────────────────────────────────────────

func getUserID(c *gin.Context) (int64, bool) {
	val, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Usuario no autenticado"})
		return 0, false
	}
	id, ok := val.(int64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Identificador de usuario inválido"})
		return 0, false
	}
	return id, true
}

func parseAccountID(c *gin.Context) (int64, bool) {
	accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || accountID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Identificador de cuenta inválido"})
		return 0, false
	}
	return accountID, true
}

func resolveIdempotencyKey(c *gin.Context, bodyKey string) string {
	if headerKey := strings.TrimSpace(c.GetHeader("Idempotency-Key")); headerKey != "" {
		return headerKey
	}
	return strings.TrimSpace(bodyKey)
}

func handleTransactionError(c *gin.Context, err error, defaultMsg string) {
	switch {
	case errors.Is(err, repositories.ErrInsufficientBalance):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Saldo insuficiente"})
	case errors.Is(err, repositories.ErrAccountNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Cuenta no encontrada"})
	case errors.Is(err, services.ErrDestinationNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Cuenta de destino no encontrada"})
	case errors.Is(err, repositories.ErrAccountClosed):
		c.JSON(http.StatusConflict, gin.H{"error": "La cuenta está cerrada y no admite operaciones"})
	case errors.Is(err, repositories.ErrUnauthorized):
		c.JSON(http.StatusForbidden, gin.H{"error": "No estás autorizado para operar con esta cuenta"})
	case errors.Is(err, repositories.ErrSameAccount):
		c.JSON(http.StatusBadRequest, gin.H{"error": "No se puede transferir a la misma cuenta"})
	case errors.Is(err, repositories.ErrInvalidAmount):
		c.JSON(http.StatusBadRequest, gin.H{"error": "El importe debe ser mayor que cero"})
	case errors.Is(err, repositories.ErrDuplicateOperation):
		c.JSON(http.StatusConflict, gin.H{"error": "Operación duplicada: la clave de idempotencia ya fue procesada"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": defaultMsg})
	}
}

// Suppress unused imports if any
var _ = models.TransactionTypeDeposit

