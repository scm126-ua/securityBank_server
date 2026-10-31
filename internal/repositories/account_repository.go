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

type AccountOwnershipRecord struct {
	HolderID   int64                  `gorm:"column:holder_id"`
	HolderName string                 `gorm:"column:holder_name"`
	HolderDNI  models.EncryptedString `gorm:"column:holder_dni"`
	AccountID  int64                  `gorm:"column:account_id"`
	IBAN       models.EncryptedString `gorm:"column:iban"`
	Role       string                 `gorm:"column:role"`
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
	hash := models.HashBlindIndex(models.GetDataEncryptionKey(), iban)

	err := r.db.WithContext(ctx).
		Where("iban_hash = ?", hash).
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

// Obtiene los datos de una cuenta únicamente cuando el usuario es uno de sus titulares.
func (r *AccountRepository) FindOwnership(
	ctx context.Context,
	userID int64,
	accountID int64,
) (*AccountOwnershipRecord, error) {
	var ownership AccountOwnershipRecord

	err := r.db.WithContext(ctx).
		Table("account_users").
		Select(`
			users.id AS holder_id,
			users.name AS holder_name,
			users.dni AS holder_dni,
			accounts.id AS account_id,
			accounts.iban AS iban,
			account_users.role AS role
		`).
		Joins("JOIN users ON users.id = account_users.user_id").
		Joins("JOIN accounts ON accounts.id = account_users.account_id").
		Where("account_users.user_id = ?", userID).
		Where("account_users.account_id = ?", accountID).
		Where("account_users.role IN ?", []string{
			models.AccountRoleOwner,
			models.AccountRoleCoOwner,
		}).
		Take(&ownership).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAccountNotFound
	}
	if err != nil {
		return nil, err
	}

	return &ownership, nil
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
		IBAN:     models.EncryptedString(iban),
		IBANHash: models.HashBlindIndex(models.GetDataEncryptionKey(), iban),
		Status:   models.AccountStatusActive,
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
	if err := createAccountAuditEvent(tx, &models.AccountAuditEvent{
		UserID:    userID,
		AccountID: &account.ID,
		Action:    models.AccountAuditActionCreate,
		Result:    models.AccountAuditResultSuccess,
	}); err != nil {
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
		if err := tx.Model(&account).Update("status", account.Status).Error; err != nil {
			return err
		}

		return createAccountAuditEvent(tx, &models.AccountAuditEvent{
			UserID:    userID,
			AccountID: &account.ID,
			Action:    models.AccountAuditActionClose,
			Result:    models.AccountAuditResultSuccess,
		})
	})

	if err != nil {
		reason, shouldAudit := accountCloseDenialReason(err)
		if shouldAudit {
			auditErr := r.recordDeniedAccountClose(
				ctx,
				userID,
				accountID,
				reason,
			)
			if auditErr != nil {
				return nil, errors.Join(err, auditErr)
			}
		}
		return nil, err
	}

	return &account, nil
}

// Registra un evento de auditoría que no forma parte de una transacción bancaria.
func (r *AccountRepository) RecordAuditEvent(
	ctx context.Context,
	event *models.AccountAuditEvent,
) error {
	return createAccountAuditEvent(r.db.WithContext(ctx), event)
}

// Inserta un evento de auditoría utilizando la transacción de la operación bancaria.
func createAccountAuditEvent(tx *gorm.DB, event *models.AccountAuditEvent) error {
	return tx.Create(event).Error
}

// Traduce los rechazos esperados a códigos de auditoría sin datos sensibles.
func accountCloseDenialReason(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrAccountNotFound):
		return models.AccountAuditReasonNotFound, true
	case errors.Is(err, ErrAccountHasBalance):
		return models.AccountAuditReasonNonZero, true
	case errors.Is(err, ErrAccountAlreadyClosed):
		return models.AccountAuditReasonAlreadyClosed, true
	default:
		return "", false
	}
}

// Guarda un cierre rechazado después de que la transacción principal haya terminado.
func (r *AccountRepository) recordDeniedAccountClose(
	ctx context.Context,
	userID int64,
	accountID int64,
	reason string,
) error {
	return createAccountAuditEvent(
		r.db.WithContext(ctx),
		&models.AccountAuditEvent{
			UserID:    userID,
			AccountID: &accountID,
			Action:    models.AccountAuditActionClose,
			Result:    models.AccountAuditResultDenied,
			Reason:    &reason,
		},
	)
}
