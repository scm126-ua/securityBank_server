package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
)

var (
	ErrInvalidEmail          = errors.New("email no válido")
	ErrInvalidAuthKey        = errors.New("clave de autenticación no válida")
	ErrInvalidDNI            = errors.New("DNI no válido")
	ErrInvalidKeyMaterial    = errors.New("material criptográfico no válido")
	ErrInvalidKeyCertificate = errors.New("certificado de claves públicas no válido")
	ErrEmailExists           = errors.New("el email ya está registrado")
	ErrDNIExists             = errors.New("el DNI ya está registrado")
)

type UserService struct {
	repo             *repositories.UserRepository
	serverPrivateKey *rsa.PrivateKey
}

func (s *UserService) FindUserByEmail(ctx context.Context,
	email string) (*models.User, error) {
	fmt.Printf("%s", email)
	return s.repo.FindByEmail(ctx, email)
}

func (s *UserService) AddFailedLoginAttempt(ctx context.Context,
	email string) (*models.User, error) {
	user, err := s.repo.AddFailedLoginAttempt(ctx, email)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserService) ResetFailedLoginAttempts(
	ctx context.Context,
	userID int64,
) error {
	return s.repo.ResetFailedLoginAttempts(ctx, userID)
}

func NewUserService(
	repo *repositories.UserRepository,
	serverPrivateKey *rsa.PrivateKey,
) *UserService {
	return &UserService{
		repo:             repo,
		serverPrivateKey: serverPrivateKey,
	}
}

// La contraseña nunca llega al servidor: el cliente envía una clave de
// autenticación derivada de ella, independiente de la que protege sus claves privadas.
func (s *UserService) Login(
	ctx context.Context,
	email string,
	authKey string,
) (*models.User, error) {
	_email := strings.ToLower(strings.TrimSpace(email))
	user, err := s.repo.FindByEmail(ctx, _email)

	if err != nil {
		return nil, err
	}

	// Verificamos la clave de autenticación con el hash almacenado
	isCorrect, err := VerifyPassword(authKey, user.PasswordHash, user.Salt)
	if err != nil {
		return nil, err
	}

	if isCorrect {
		return user, nil
	}

	return nil, errors.New("La contraseña no coincide")

}

// Comprueba la firma del desafío con la clave pública registrada del usuario.
func (s *UserService) VerifyChallenge(
	ctx context.Context,
	userID int64,
	challenge []byte,
	signature string,
) (*models.User, error) {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.PublicKey == nil ||
		user.SigningPublicKey == nil ||
		user.PublicKeysSignature == nil ||
		s.serverPrivateKey == nil {
		return nil, ErrKeyMaterialUnavailable
	}

	if err := VerifyUserPublicKeys(
		&s.serverPrivateKey.PublicKey,
		user.Email,
		*user.PublicKey,
		*user.SigningPublicKey,
		*user.PublicKeysSignature,
	); err != nil {
		return nil, ErrInvalidKeyCertificate
	}

	if err := verifyChallengeSignature(*user.SigningPublicKey, challenge, signature); err != nil {
		return nil, err
	}

	return user, nil
}

// PBKDF2-HMAC-SHA256 + salt aleatoria + muchas iteraciones.
func (s *UserService) Register(
	ctx context.Context,
	email string,
	authKey string,
	name string,
	surname string,
	dni string,
	keyMaterial UserKeyMaterial,
	totpSecret []byte,
	totpEnabled bool,
) (*models.User, *models.Account, error) {

	// Normalizamos y validamos el email, la clave de autenticación y el DNI.
	// La política de contraseñas solo puede comprobarse en el cliente.
	_email := strings.ToLower(strings.TrimSpace(email))
	_dni := strings.ToUpper(strings.TrimSpace(dni))

	parsedEmail, err := mail.ParseAddress(_email)
	if err != nil || parsedEmail.Address != _email {
		return nil, nil, ErrInvalidEmail
	}

	if !validAuthKey(authKey) {
		return nil, nil, ErrInvalidAuthKey
	}

	if !ValidateSpanishDNI(_dni) {
		return nil, nil, ErrInvalidDNI
	}

	validatedKeys, err := validateUserKeyMaterial(keyMaterial)
	if err != nil {
		return nil, nil, err
	}

	// Comprobamos que el email no esté ya registrado
	_, err = s.repo.FindByEmail(ctx, _email)

	if err == nil {
		return nil, nil, ErrEmailExists
	}

	if !errors.Is(err, repositories.ErrUserNotFound) {
		return nil, nil, err
	}

	// Comprobamos que el DNI no esté ya registrado
	_, err = s.repo.FindByDNI(ctx, _dni)

	if err == nil {
		return nil, nil, ErrDNIExists
	}

	if !errors.Is(err, repositories.ErrUserNotFound) {
		return nil, nil, err
	}

	// LOGICA DE CIFRADO
	// Generamos una clave de 32 bytes

	// Generar Hash de la clave de autenticación (clave + salt)
	passwordHash, salt, err := HashPassword(authKey)
	if err != nil {
		return nil, nil, err
	}

	publicKeysSignature, err := SignUserPublicKeys(
		s.serverPrivateKey,
		_email,
		validatedKeys.publicKey,
		validatedKeys.signingPublicKey,
	)
	if err != nil {
		return nil, nil, err
	}

	user := &models.User{
		Email:                  _email,
		Name:                   strings.TrimSpace(name + " " + surname),
		DNI:                    models.EncryptedString(_dni),
		DNIHash:                models.HashBlindIndex(models.GetDataEncryptionKey(), _dni),
		Salt:                   salt,
		PasswordHash:           passwordHash,
		Role:                   models.UserRoleClient,
		PublicKey:              &validatedKeys.publicKey,
		SigningPublicKey:       &validatedKeys.signingPublicKey,
		PublicKeysSignature:    &publicKeysSignature,
		EncryptedPrivateKeys:   validatedKeys.ciphertext,
		PrivateKeysSalt:        validatedKeys.salt,
		PrivateKeysNonce:       validatedKeys.nonce,
		PrivateKeysIterations:  &validatedKeys.iterations,
		PrivateKeysVersion:     &validatedKeys.version,
		FailedLoginAttempts:    0,
		LastFailedLoginAttempt: nil,
	}

	if len(totpSecret) > 0 && totpEnabled {
		user.TotpSecret = totpSecret
		user.TotpEnabled = true
		now := time.Now()
		user.TotpConfirmedAt = &now
	}

	iban, err := GenerateSpanishIBAN("0036", "1234")
	if err != nil {
		return nil, nil, err
	}

	account, err := s.repo.CreateWithAccount(ctx, user, iban)
	if err != nil {
		return nil, nil, err
	}

	return user, account, nil
}
