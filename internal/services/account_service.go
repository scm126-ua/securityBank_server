// Gestiona la lógica y CRUDs para las cuentas bancarias

package services

import (
	"context"
	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
)

type AccountService struct {
	repo *repositories.AccountRepository
}

func NewAccountService(
	repo *repositories.AccountRepository,
) *AccountService {
	return &AccountService{repo: repo}
}

// Crear una cuenta
func (s *AccountService) CreateAccount(
	ctx context.Context,
	user *models.User,
) (*models.Account, error) {

	// Generar IBAN
	iban, errIban := GenerateSpanishIBAN("0036","1234")

	if errIban != nil{
		return nil, errIban 
	}

	account, err := s.repo.Create(ctx, user, iban)

	if err != nil {
		return account, err
	}

	return account, nil
}

func (s *AccountService) FindUserAccounts(ctx context.Context,
	userId int64) ([]models.Account, error) {

	accounts, err := s.repo.FindByUser(ctx, userId)

	return accounts, err
}
