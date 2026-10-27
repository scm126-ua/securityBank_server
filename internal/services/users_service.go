package services

import (
	"context"
	"errors"

	"net/mail"
	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
	"strings"
)

var (
	ErrInvalidEmail    = errors.New("email no válido")
	ErrInvalidPassword = errors.New("contraseña no válida")
	ErrInvalidDNI      = errors.New("DNI no válido")
	ErrEmailExists     = errors.New("el email ya está registrado")
)

type UserService struct {
	repo *repositories.UserRepository
}

func NewUserService(
	repo *repositories.UserRepository,
) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) Login(
	ctx context.Context,
	email string,
	password string,
) (*models.User, error) {
	user, err := s.repo.FindByEmail(ctx, email)

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

// PBKDF2-HMAC-SHA256 + salt aleatoria + muchas iteraciones.
func (s *UserService) Register(
	ctx context.Context,
	email string,
	password string,
	name string,
	surname string,
	dni string,
) (*models.User, error) {

	// Normalizamos y validamos el email, la contraseña y el DNI
	_email := strings.ToLower(strings.TrimSpace(email))
	_dni := strings.ToUpper(strings.TrimSpace(dni))

	parsedEmail, err := mail.ParseAddress(_email)
	if err != nil || parsedEmail.Address != _email {
		return nil, ErrInvalidEmail
	}

	if !ValidatePassword(password) {
		return nil, ErrInvalidPassword
	}

	if !ValidateSpanishDNI(_dni) {
		return nil, ErrInvalidDNI
	}

	// Comprobamos que el email no esté ya registrado
	_, err = s.repo.FindByEmail(ctx, _email)

	if err == nil {
		return nil, ErrEmailExists
	}

	if !errors.Is(err, repositories.ErrUserNotFound) {
		return nil, err
	}

	// LOGICA DE CIFRADO
	// Generamos una clave de 32 bytes

	// Generar Hash de contraseña (la password es password + salt)
	passwordHash, salt, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Email:        _email,
		Name:         strings.TrimSpace(name + " " + surname),
		DNI:          _dni,
		Salt:         salt,
		PasswordHash: passwordHash,
		Role:         "CLIENT",
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}
