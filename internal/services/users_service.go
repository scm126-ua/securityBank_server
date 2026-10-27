package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/mail"
	"strings"

	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
)

var (
	ErrInvalidEmail          = errors.New("email no válido")
	ErrInvalidPassword       = errors.New("contraseña no válida")
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

func NewUserService(
	repo *repositories.UserRepository,
	serverPrivateKey *rsa.PrivateKey,
) *UserService {
	return &UserService{
		repo:             repo,
		serverPrivateKey: serverPrivateKey,
	}
}

func (s *UserService) Login(
	ctx context.Context,
	email string,
	password string,
) (*models.User, error) {
	_email := strings.ToLower(strings.TrimSpace(email))
	user, err := s.repo.FindByEmail(ctx, _email)

	if err != nil {
		return nil, err
	}

	// Verificamos la contraseña proporcionada con el hash almacenado
	isCorrect, err := VerifyPassword(password, user.PasswordHash, user.Salt)
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
	password string,
	name string,
	surname string,
	dni string,
	keyMaterial UserKeyMaterial,
) (*models.User, *models.Account, error) {

	// Normalizamos y validamos el email, la contraseña y el DNI
	_email := strings.ToLower(strings.TrimSpace(email))
	_dni := strings.ToUpper(strings.TrimSpace(dni))

	parsedEmail, err := mail.ParseAddress(_email)
	if err != nil || parsedEmail.Address != _email {
		return nil, nil, ErrInvalidEmail
	}

	if !ValidatePassword(password) {
		return nil, nil, ErrInvalidPassword
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

	// Generar Hash de contraseña (la password es password + salt)
	passwordHash, salt, err := HashPassword(password)
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
		Email:                 _email,
		Name:                  strings.TrimSpace(name + " " + surname),
		DNI:                   _dni,
		Salt:                  salt,
		PasswordHash:          passwordHash,
		Role:                  models.UserRoleClient,
		PublicKey:             &validatedKeys.publicKey,
		SigningPublicKey:      &validatedKeys.signingPublicKey,
		PublicKeysSignature:   &publicKeysSignature,
		EncryptedPrivateKeys:  validatedKeys.ciphertext,
		PrivateKeysSalt:       validatedKeys.salt,
		PrivateKeysNonce:      validatedKeys.nonce,
		PrivateKeysIterations: &validatedKeys.iterations,
		PrivateKeysVersion:    &validatedKeys.version,
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
