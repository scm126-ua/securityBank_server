package services

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"io"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"securityBank_server/internal/repositories"
)

var (
	ErrTOTPAlreadyEnabled = errors.New("el 2FA ya está activado")
	ErrTOTPNotConfigured  = errors.New("el 2FA no está configurado")
	ErrInvalidTOTP        = errors.New("código 2FA no válido")
	ErrTOTPEncryption     = errors.New("error al cifrar o descifrar el secreto 2FA")
)

type TOTPSetupResponse struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauth_url"`
	QRCode     string `json:"qr_code"`
}

type TOTPService struct {
	repo      *repositories.UserRepository
	cipherKey []byte
}

// encryptionKey debe contener exactamente 32 bytes.
func NewTOTPService(
	repo *repositories.UserRepository,
	encryptionKey []byte,
) (*TOTPService, error) {
	if repo == nil || len(encryptionKey) != 32 {
		return nil, ErrTOTPEncryption
	}

	keyCopy := make([]byte, len(encryptionKey))
	copy(keyCopy, encryptionKey)

	return &TOTPService{
		repo:      repo,
		cipherKey: keyCopy,
	}, nil
}

// Cifra el secreto TOTP utilizando AES-256-GCM.
// El nonce se almacena junto al ciphertext.
func (s *TOTPService) encryptSecret(secret string) ([]byte, error) {
	block, err := aes.NewCipher(s.cipherKey)
	if err != nil {
		return nil, ErrTOTPEncryption
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrTOTPEncryption
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrTOTPEncryption
	}

	encrypted := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return encrypted, nil
}

func (s *TOTPService) decryptSecret(encrypted []byte) (string, error) {
	block, err := aes.NewCipher(s.cipherKey)
	if err != nil {
		return "", ErrTOTPEncryption
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrTOTPEncryption
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return "", ErrTOTPEncryption
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrTOTPEncryption
	}

	return string(plaintext), nil
}

func keyToQRCode(key *otp.Key) string {
	img, err := key.Image(200, 200)
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// SetupTOTP genera un secreto, lo almacena pendiente y devuelve URL, clave y código QR.
func (s *TOTPService) SetupTOTP(
	ctx context.Context,
	userID int64,
) (*TOTPSetupResponse, error) {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.TotpEnabled {
		return nil, ErrTOTPAlreadyEnabled
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SecurityBank",
		AccountName: user.Email,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("generar secreto TOTP: %w", err)
	}

	encryptedSecret, err := s.encryptSecret(key.Secret())
	if err != nil {
		return nil, err
	}

	if err := s.repo.SaveTOTPSecret(ctx, userID, encryptedSecret); err != nil {
		return nil, err
	}

	return &TOTPSetupResponse{
		Secret:     key.Secret(),
		OtpauthURL: key.URL(),
		QRCode:     keyToQRCode(key),
	}, nil
}

// GenerateRegistrationTOTP genera una clave TOTP para el formulario de registro.
func (s *TOTPService) GenerateRegistrationTOTP(email string) (*TOTPSetupResponse, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SecurityBank",
		AccountName: email,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("generar secreto TOTP: %w", err)
	}

	return &TOTPSetupResponse{
		Secret:     key.Secret(),
		OtpauthURL: key.URL(),
		QRCode:     keyToQRCode(key),
	}, nil
}

// EncryptSecret cifra un secreto en texto plano.
func (s *TOTPService) EncryptSecret(secret string) ([]byte, error) {
	return s.encryptSecret(secret)
}

// DecryptSecret descifra un secreto cifrado.
func (s *TOTPService) DecryptSecret(encrypted []byte) (string, error) {
	return s.decryptSecret(encrypted)
}

// ValidateCode valida un código TOTP de 6 dígitos contra un secreto en texto plano.
func (s *TOTPService) ValidateCode(secret string, code string) (bool, error) {
	return validateTOTP(secret, code)
}

// IsTOTPEnabled indica si el usuario tiene el 2FA activo.
func (s *TOTPService) IsTOTPEnabled(ctx context.Context, userID int64) (bool, error) {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return false, err
	}
	return user.TotpEnabled, nil
}

// EnableTOTP comprueba el primer código y activa el 2FA.
func (s *TOTPService) EnableTOTP(
	ctx context.Context,
	userID int64,
	code string,
) error {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	if user.TotpEnabled {
		return ErrTOTPAlreadyEnabled
	}

	if len(user.TotpSecret) == 0 {
		return ErrTOTPNotConfigured
	}

	secret, err := s.decryptSecret(user.TotpSecret)
	if err != nil {
		return err
	}

	valid, err := validateTOTP(secret, code)
	if err != nil {
		return err
	}

	if !valid {
		return ErrInvalidTOTP
	}

	return s.repo.EnableTOTP(ctx, userID)
}

func (s *TOTPService) VerifyTOTP(
	ctx context.Context,
	userID int64,
	code string,
) error {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	if !user.TotpEnabled || len(user.TotpSecret) == 0 {
		return ErrTOTPNotConfigured
	}

	secret, err := s.decryptSecret(user.TotpSecret)
	if err != nil {
		return err
	}

	valid, err := validateTOTP(secret, code)
	if err != nil {
		return err
	}

	if !valid {
		return ErrInvalidTOTP
	}

	return nil
}

// DisableTOTP exige un código válido antes de eliminar la configuración.
func (s *TOTPService) DisableTOTP(
	ctx context.Context,
	userID int64,
	code string,
) error {
	if err := s.VerifyTOTP(ctx, userID, code); err != nil {
		return err
	}

	return s.repo.DisableTOTP(ctx, userID)
}

func validateTOTP(secret string, code string) (bool, error) {
	if len(code) != 6 {
		return false, ErrInvalidTOTP
	}

	valid, err := totp.ValidateCustom(
		code,
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)

	if err != nil {
		return false, err
	}

	return valid, nil
}

// Utilidad para leer la clave desde una variable de entorno Base64.
func DecodeTOTPEncryptionKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, ErrTOTPEncryption
	}

	return key, nil
}
