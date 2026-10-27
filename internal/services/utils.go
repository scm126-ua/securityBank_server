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

	// Calcular por separado los dos dígitos de control nacionales.
	bankBranchCheck := calculateAccountCheckDigit("00" + bankCode + branchCode)
	accountCheck := calculateAccountCheckDigit(accountNumber)

	domestic := fmt.Sprintf("%s%s%d%d%s",
		bankCode, branchCode, bankBranchCheck, accountCheck, accountNumber)

	// Calcular los dígitos de control internacionales.
	// ES00 equivale a E=14, S=28, 0, 0.
	checkInput := domestic + "142800"
	checkDigits := 98 - mod97(checkInput)

	iban := fmt.Sprintf("ES%02d%s", checkDigits, domestic)
	return iban, nil
}

// Calcula un dígito de control nacional mediante módulo 11.
func calculateAccountCheckDigit(value string) int {
	weights := [...]int{1, 2, 4, 8, 5, 10, 9, 7, 3, 6}
	sum := 0

	for i, digit := range value {
		sum += int(digit-'0') * weights[i]
	}

	checkDigit := 11 - sum%11
	if checkDigit == 10 {
		return 1
	}
	if checkDigit == 11 {
		return 0
	}

	return checkDigit
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

// Comprueba la longitud y la presencia de letras y números.
func ValidatePassword(password string) bool {
	if len(password) < 8 || len(password) > 72 {
		return false
	}

	hasLetter := false
	hasNumber := false

	for _, character := range password {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') {
			hasLetter = true
		}
		if character >= '0' && character <= '9' {
			hasNumber = true
		}
	}

	return hasLetter && hasNumber
}

// Comprueba el formato y la letra de control de un DNI español.
func ValidateSpanishDNI(dni string) bool {
	dni = strings.ToUpper(strings.TrimSpace(dni))

	if len(dni) != 9 || !isNumeric(dni[:8]) {
		return false
	}

	number, err := strconv.Atoi(dni[:8])
	if err != nil {
		return false
	}

	const controlLetters = "TRWAGMYFPDXBNJZSQVHLCKE"
	return dni[8] == controlLetters[number%len(controlLetters)]
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
