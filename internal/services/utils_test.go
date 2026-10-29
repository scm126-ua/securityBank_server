package services

import (
	"strings"
	"testing"
)

// Comprueba que los IBAN generados tienen un formato válido.
func TestGenerateSpanishIBAN(t *testing.T) {
	for i := 0; i < 100; i++ {
		iban, err := GenerateSpanishIBAN("0036", "1234")
		if err != nil {
			t.Fatalf("no se pudo generar el IBAN: %v", err)
		}

		if len(iban) != 24 {
			t.Fatalf("el IBAN debe tener 24 caracteres: %q", iban)
		}
		if !strings.HasPrefix(iban, "ES") || !isNumeric(iban[2:]) {
			t.Fatalf("el IBAN debe comenzar por ES y continuar con 22 dígitos: %q", iban)
		}
		if !ValidateSpanishIBAN(iban) {
			t.Fatalf("el IBAN generado no supera su validación: %q", iban)
		}
	}
}

// Verifica los dígitos de control con un ejemplo conocido.
func TestSpanishAccountCheckDigits(t *testing.T) {
	bankBranchCheck := calculateAccountCheckDigit("0000120345")
	accountCheck := calculateAccountCheckDigit("0000067890")

	if bankBranchCheck != 0 || accountCheck != 3 {
		t.Fatalf("se esperaban los dígitos de control 03 y se obtuvieron %d%d",
			bankBranchCheck, accountCheck)
	}

	if !ValidateSpanishIBAN("ES0700120345030000067890") {
		t.Fatal("el IBAN oficial de ejemplo debería ser válido")
	}
}

// Comprueba DNIs válidos, normalizados y con formatos incorrectos.
func TestValidateSpanishDNI(t *testing.T) {
	tests := []struct {
		dni   string
		valid bool
	}{
		{dni: "12345678Z", valid: true},
		{dni: " 12345678z ", valid: true},
		{dni: "12345678A", valid: false},
		{dni: "1234", valid: false},
		{dni: "ABCDEFGHZ", valid: false},
	}

	for _, test := range tests {
		if result := ValidateSpanishDNI(test.dni); result != test.valid {
			t.Errorf("ValidateSpanishDNI(%q) = %v; se esperaba %v",
				test.dni, result, test.valid)
		}
	}
}
