package repositories

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"securityBank_server/internal/models"
)

var ErrUserNotFound = errors.New("usuario no encontrado")

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*models.User, error) {
	var user models.User

	err := r.db.WithContext(ctx).
		Where("email = ?", email).
		First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Busca un usuario por su DNI y distingue cuando no existe.
func (r *UserRepository) FindByDNI(
	ctx context.Context,
	dni string,
) (*models.User, error) {
	var user models.User

	err := r.db.WithContext(ctx).
		Where("dni = ?", dni).
		First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Crea el usuario y su cuenta inicial dentro de la misma transacción.
func (r *UserRepository) CreateWithAccount(
	ctx context.Context,
	user *models.User,
	iban string,
) (*models.Account, error) {
	var account *models.Account

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return err
		}

		var err error
		account, err = createAccount(tx, user.ID, iban)
		return err
	})

	if err != nil {
		return nil, err
	}

	return account, nil
}
