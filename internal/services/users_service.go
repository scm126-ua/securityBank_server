package services

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
)

var (
	ErrInvalidEmail    = errors.New("email no válido")
	ErrInvalidPassword = errors.New("contraseña no válida")
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

	// Logica para verificar la contraseña aqui

	return user, nil
}

func (s *UserService) Register(
	ctx context.Context,
	email string,
	password string,
	name string,
	dni string,
) (*models.User, error) {

	// Normalizamos y validamos el email y la contraseña
	_email := strings.ToLower(strings.TrimSpace(email))

	parsedEmail, err := mail.ParseAddress(_email)
	if err != nil || parsedEmail.Address != _email {
		return nil, ErrInvalidEmail
	}

	if len(password) < 8 || len(password) > 72 {
		return nil, ErrInvalidPassword
	}

	// Comprobamos que el email no esté ya registrado
	_, err = s.repo.FindByEmail(ctx, _email)

	if err == nil {
		return nil, ErrEmailExists
	}

	if !errors.Is(err, repositories.ErrUserNotFound) {
		return nil, err
	}

	// Generar Hash de contraseña
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Email:        email,
		Name:         name,
		DNI:          dni,
		PasswordHash: string(passwordHash),
		Role:         "CLIENT",
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}
