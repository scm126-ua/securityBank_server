package repositories

import (
	"context"
	"errors"
	"time"

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

func (r *UserRepository) AddFailedLoginAttempt(
	ctx context.Context,
	email string,
) (*models.User, error) {

	// Registramos el intento fallido
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("email = ?", email).
		Updates(map[string]interface{}{
			"failed_login_attempts":     gorm.Expr("failed_login_attempts + 1"),
			"last_failed_login_attempt": time.Now(),
		})

	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, ErrUserNotFound
	}

	// Recuperamos el usuario con el contador actualizado
	var user models.User

	err := r.db.WithContext(ctx).
		Where("email = ?", email).
		First(&user).Error

	if err != nil {
		return nil, err
	}

	lastAttempt := user.FailedLoginAttempts

	// Cada 3 intentos fallidos, aplicamos un bloqueo de 5 minutos por intento.
	if lastAttempt%3 == 0 {
		lockedUntil := time.Now().Add(
			time.Duration(5*lastAttempt) * time.Minute,
		)

		result = r.db.WithContext(ctx).
			Model(&models.User{}).
			Where("id = ?", user.ID).
			Update("locked_until", lockedUntil)

		if result.Error != nil {
			return nil, result.Error
		}

		if result.RowsAffected == 0 {
			return nil, ErrUserNotFound
		}

		// Actualizamos el valor en el objeto que devolveremos.
		user.LockedUntil = &lockedUntil
	}

	return &user, nil
}

// ResetFailedLoginAttempts limpia los intentos fallidos
// y cualquier bloqueo asociado al usuario.
func (r *UserRepository) ResetFailedLoginAttempts(
	ctx context.Context,
	userID int64,
) error {
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"failed_login_attempts":     0,
			"last_failed_login_attempt": nil,
			"locked_until":              nil,
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// Busca un usuario por su identificador y distingue cuando no existe.
func (r *UserRepository) FindByID(
	ctx context.Context,
	userID int64,
) (*models.User, error) {
	var user models.User

	err := r.db.WithContext(ctx).First(&user, userID).Error
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

func (r *UserRepository) TemporalLoginBlock(
	ctx context.Context,
	email string) {

}
