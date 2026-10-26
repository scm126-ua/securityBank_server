package services

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// GenerateSpanishIBAN genera un IBAN español sintácticamente válido.
// bankCode: código de entidad de 4 dígitos.
// branchCode: código de sucursal de 4 dígitos.
func GenerateSpanishIBAN(bankCode, branchCode string) (string, error) {
	if len(bankCode) != 4 || !isNumeric(bankCode) {
		return "", fmt.Errorf("el código bancario debe tener 4 dígitos")
	}

	if len(branchCode) != 4 || !isNumeric(branchCode) {
		return "", fmt.Errorf("el código de sucursal debe tener 4 dígitos")
	}

	// Generar aleatoriamente los 10 dígitos de la cuenta.
	accountNumber := ""
	for i := 0; i < 10; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("error generando la cuenta: %w", err)
		}
		accountNumber += n.String()
	}

	// Calcular los dígitos de control nacionales.
	basicAccount := bankCode + branchCode + "00" + accountNumber
	nationalCheck := 11 - mod97(basicAccount)

	switch nationalCheck {
	case 11:
		nationalCheck = 0
	case 10:
		nationalCheck = 1
	}

	domestic := fmt.Sprintf("%s%s%02d%s",
		bankCode, branchCode, nationalCheck, accountNumber)

	// Calcular los dígitos de control internacionales.
	// ES00 equivale a E=14, S=28, 0, 0.
	checkInput := domestic + "142800"
	checkDigits := 98 - mod97(checkInput)

	iban := fmt.Sprintf("ES%02d%s", checkDigits, domestic)
	return iban, nil
}

func mod97(value string) int {
	remainder := 0
	for _, digit := range value {
		remainder = (remainder*10 + int(digit-'0')) % 97
	}
	return remainder
}

func isNumeric(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ValidateSpanishIBAN comprueba los dígitos de control de un IBAN español.
func ValidateSpanishIBAN(iban string) bool {
	iban = strings.ToUpper(strings.ReplaceAll(iban, " ", ""))

	if len(iban) != 24 || !strings.HasPrefix(iban, "ES") {
		return false
	}

	// Mover los cuatro primeros caracteres al final.
	rearranged := iban[4:] + iban[:4]

	// Convertir las letras a números: A=10, B=11, ..., Z=35.
	var numeric strings.Builder
	for _, c := range rearranged {
		if c >= '0' && c <= '9' {
			numeric.WriteRune(c)
		} else if c >= 'A' && c <= 'Z' {
			numeric.WriteString(strconv.Itoa(int(c-'A') + 10))
		} else {
			return false
		}
	}

	return mod97(numeric.String()) == 1
}