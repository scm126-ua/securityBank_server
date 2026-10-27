package repositories

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"securityBank_server/internal/models"
)

var (
	ErrAccountNotFound      = errors.New("Cuenta no encontrada")
	ErrAccountHasBalance    = errors.New("La cuenta tiene saldo")
	ErrAccountAlreadyClosed = errors.New("La cuenta ya está cerrada")
)

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

// Buscar todas las cuentas del usuario

func (r *AccountRepository) FindByUser(
	ctx context.Context,
	userId int64,
) ([]models.Account, error) {
	accounts := make([]models.Account, 0)

	err := r.db.WithContext(ctx).
		Joins("JOIN account_users ON account_users.account_id = accounts.id").
		Where("account_users.user_id = ?", userId).
		Find(&accounts).Error

	if err != nil {
		return nil, err
	}

	return accounts, nil
}

func (r *AccountRepository) Create(
	ctx context.Context,
	userID int64,
	iban string,
) (*models.Account, error) {
	var account *models.Account

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		account, err = createAccount(tx, userID, iban)
		return err
	})

	if err != nil {
		return nil, err
	}

	return account, nil
}

// Crea una cuenta y asigna su propietario usando la transacción recibida.
func createAccount(
	tx *gorm.DB,
	userID int64,
	iban string,
) (*models.Account, error) {
	account := &models.Account{
		IBAN:   iban,
		Status: models.AccountStatusActive,
	}

	if err := tx.Create(account).Error; err != nil {
		return nil, err
	}

	accountUser := models.AccountUser{
		AccountID: account.ID,
		UserID:    userID,
		Role:      "OWNER",
	}

	if err := tx.Create(&accountUser).Error; err != nil {
		return nil, err
	}

	return account, nil
}

// Cierra una cuenta del propietario dentro de una transacción.
func (r *AccountRepository) Close(
	ctx context.Context,
	userID int64,
	accountID int64,
) (*models.Account, error) {
	var account models.Account

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var accountUser models.AccountUser
		err := tx.Where(
			"user_id = ? AND account_id = ? AND role = ?",
			userID,
			accountID,
			models.AccountRoleOwner,
		).First(&accountUser).Error

		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAccountNotFound
		}
		if err != nil {
			return err
		}

		err = tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&account, accountID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAccountNotFound
		}
		if err != nil {
			return err
		}

		if account.Status == models.AccountStatusClosed {
			return ErrAccountAlreadyClosed
		}
		if !account.Balance.IsZero() {
			return ErrAccountHasBalance
		}

		account.Status = models.AccountStatusClosed
		return tx.Model(&account).Update("status", account.Status).Error
	})

	if err != nil {
		return nil, err
	}

	return &account, nil
}
