package repositories

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"securityBank_server/internal/models"
)

var ErrAccountNotFound = errors.New("Cuenta no encontrada")

type AccountRepository struct {
	db *gorm.DB
}

func NewAccountRepository(db *gorm.DB) *AccountRepository {
	return &AccountRepository{db: db}
}

// Buscar una cuenta por IBAN
func (r *AccountRepository) FindByIBAN(
	ctx context.Context,
	iban string,
) (*models.Account, error) {
	var account models.Account

	err := r.db.WithContext(ctx).
		Where("iban = ?", iban).
		First(&account).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAccountNotFound
	}

	if err != nil {
		return nil, err
	}

	return &account, nil
}

// Buscar todas las cuentas del

func (r *AccountRepository) FindByUser(
	ctx context.Context,
	userId int64,
) ([]models.Account, error) {
	var accounts []models.Account

	err := r.db.WithContext(ctx).
		Joins("JOIN account_users ON account_users.account_id = accounts.id").
		Where("account_users.user_id = ?", userId).
		Find(&accounts).Error

	if err != nil {
		return nil, err
	}

	if len(accounts) == 0 {
		return nil, ErrAccountNotFound
	}

	return accounts, nil
}

func (r *AccountRepository) Create(
	ctx context.Context,
	user *models.User,
	iban string,
) (*models.Account, error) {
	var account *models.Account

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		account = &models.Account{
			IBAN:   iban,
			Status: models.AccountStatusActive,
		}

		if err := tx.Create(account).Error; err != nil {
			return err
		}

		accountUser := models.AccountUser{
			AccountID: account.ID,
			UserID:    user.ID,
			Role:      "OWNER",
		}

		if err := tx.Create(&accountUser).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return account, nil
}
