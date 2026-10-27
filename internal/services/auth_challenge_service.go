package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	challengeRandomSize = 32
	challengeTTL        = 2 * time.Minute
)

var ErrInvalidChallenge = errors.New("desafío inválido o expirado")

type AuthChallenge struct {
	UserID    int64
	Nonce     []byte
	ExpiresAt time.Time
}

type AuthChallengeService struct {
	mu         sync.Mutex
	challenges map[string]AuthChallenge
	now        func() time.Time
}

// Crea un almacén temporal de desafíos con reloj del sistema.
func NewAuthChallengeService() *AuthChallengeService {
	return &AuthChallengeService{
		challenges: make(map[string]AuthChallenge),
		now:        time.Now,
	}
}

// Genera un identificador y un nonce aleatorios asociados al usuario.
func (s *AuthChallengeService) Create(userID int64) (string, []byte, time.Time, error) {
	if userID <= 0 {
		return "", nil, time.Time{}, ErrInvalidChallenge
	}

	idBytes, err := randomChallengeBytes()
	if err != nil {
		return "", nil, time.Time{}, err
	}

	nonce, err := randomChallengeBytes()
	if err != nil {
		return "", nil, time.Time{}, err
	}

	id := base64.RawURLEncoding.EncodeToString(idBytes)
	now := s.now()
	expiresAt := now.Add(challengeTTL)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.removeExpired(now)
	s.challenges[id] = AuthChallenge{
		UserID:    userID,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}

	return id, append([]byte(nil), nonce...), expiresAt, nil
}

// Recupera y elimina un desafío para impedir que pueda reutilizarse.
func (s *AuthChallengeService) Consume(id string) (AuthChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	challenge, exists := s.challenges[id]
	delete(s.challenges, id)

	if !exists || !now.Before(challenge.ExpiresAt) {
		return AuthChallenge{}, ErrInvalidChallenge
	}

	return challenge, nil
}

// Elimina las entradas que ya han superado su fecha de caducidad.
func (s *AuthChallengeService) removeExpired(now time.Time) {
	for id, challenge := range s.challenges {
		if !now.Before(challenge.ExpiresAt) {
			delete(s.challenges, id)
		}
	}
}

// Obtiene bytes impredecibles del generador criptográfico del sistema.
func randomChallengeBytes() ([]byte, error) {
	value := make([]byte, challengeRandomSize)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("no se pudo generar el desafío: %w", err)
	}

	return value, nil
}
