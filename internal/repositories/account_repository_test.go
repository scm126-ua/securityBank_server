package repositories

import (
	"errors"
	"testing"

	"securityBank_server/internal/models"
)

// Comprueba que cada rechazo esperado utiliza un código de auditoría estable.
func TestAccountCloseDenialReasons(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "cuenta no encontrada",
			err:      ErrAccountNotFound,
			expected: models.AccountAuditReasonNotFound,
		},
		{
			name:     "saldo distinto de cero",
			err:      ErrAccountHasBalance,
			expected: models.AccountAuditReasonNonZero,
		},
		{
			name:     "cuenta ya cerrada",
			err:      ErrAccountAlreadyClosed,
			expected: models.AccountAuditReasonAlreadyClosed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reason, shouldAudit := accountCloseDenialReason(test.err)
			if !shouldAudit || reason != test.expected {
				t.Fatalf("motivo inesperado: %q", reason)
			}
		})
	}
}

// Comprueba que los fallos internos no se registran como rechazos del usuario.
func TestUnexpectedAccountCloseErrorIsNotDenied(t *testing.T) {
	reason, shouldAudit := accountCloseDenialReason(errors.New("error interno"))
	if shouldAudit || reason != "" {
		t.Fatal("un error interno no debe registrarse como operación denegada")
	}
}
