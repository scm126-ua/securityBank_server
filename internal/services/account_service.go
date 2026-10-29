// Gestiona la lógica y CRUDs para las cuentas bancarias

package services

import (
	"context"
	"crypto/rsa"
	"errors"

	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
)

var (
	ErrAccountNotFound      = repositories.ErrAccountNotFound
	ErrAccountHasBalance    = repositories.ErrAccountHasBalance
	ErrAccountAlreadyClosed = repositories.ErrAccountAlreadyClosed
)

type AccountService struct {
	repo             *repositories.AccountRepository
	serverPrivateKey *rsa.PrivateKey
}

func NewAccountService(
	repo *repositories.AccountRepository,
	serverPrivateKey *rsa.PrivateKey,
) *AccountService {
	return &AccountService{
		repo:             repo,
		serverPrivateKey: serverPrivateKey,
	}
}

// Crear una cuenta
func (s *AccountService) CreateAccount(
	ctx context.Context,
	userID int64,
) (*models.Account, error) {

	// Generar IBAN
	iban, errIban := GenerateSpanishIBAN("0036", "1234")

	if errIban != nil {
		return nil, errIban
	}

	account, err := s.repo.Create(ctx, userID, iban)

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

// Solicita el cierre de una cuenta del usuario autenticado.
func (s *AccountService) CloseAccount(
	ctx context.Context,
	userID int64,
	accountID int64,
) (*models.Account, error) {
	return s.repo.Close(ctx, userID, accountID)
}

// Genera un certificado firmado después de comprobar la titularidad de la cuenta.
// Si la emisión no puede auditarse, el certificado no se entrega.
func (s *AccountService) CreateOwnershipCertificate(
	ctx context.Context,
	userID int64,
	accountID int64,
) (SignedAccountOwnershipCertificate, error) {
	ownership, err := s.repo.FindOwnership(ctx, userID, accountID)
	if errors.Is(err, ErrAccountNotFound) {
		reason := models.AccountAuditReasonNotFound
		auditErr := s.repo.RecordAuditEvent(ctx, &models.AccountAuditEvent{
			UserID:    userID,
			AccountID: &accountID,
			Action:    models.AccountAuditActionIssueCertificate,
			Result:    models.AccountAuditResultDenied,
			Reason:    &reason,
		})
		return SignedAccountOwnershipCertificate{}, errors.Join(err, auditErr)
	}
	if err != nil {
		return SignedAccountOwnershipCertificate{}, err
	}

	certificate, err := CreateAccountOwnershipCertificate(
		s.serverPrivateKey,
		AccountOwnershipData{
			HolderID:   ownership.HolderID,
			HolderName: ownership.HolderName,
			HolderDNI:  ownership.HolderDNI,
			AccountID:  ownership.AccountID,
			IBAN:       ownership.IBAN,
			Role:       ownership.Role,
		},
	)
	if err != nil {
		return SignedAccountOwnershipCertificate{}, err
	}

	err = s.repo.RecordAuditEvent(ctx, &models.AccountAuditEvent{
		UserID:        userID,
		AccountID:     &accountID,
		Action:        models.AccountAuditActionIssueCertificate,
		Result:        models.AccountAuditResultSuccess,
		CertificateID: &certificate.Certificate.CertificateID,
	})
	if err != nil {
		return SignedAccountOwnershipCertificate{}, err
	}

	return certificate, nil
}
