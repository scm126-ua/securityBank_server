package services

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// Comprueba que cada desafío tenga valores aleatorios diferentes.
func TestAuthChallengesAreUnique(t *testing.T) {
	service := NewAuthChallengeService()

	firstID, firstNonce, _, err := service.Create(1)
	if err != nil {
		t.Fatalf("no se pudo crear el primer desafío: %v", err)
	}

	secondID, secondNonce, _, err := service.Create(1)
	if err != nil {
		t.Fatalf("no se pudo crear el segundo desafío: %v", err)
	}

	if firstID == secondID || bytes.Equal(firstNonce, secondNonce) {
		t.Fatal("los desafíos generados deben ser diferentes")
	}

	if len(firstNonce) != challengeRandomSize || len(secondNonce) != challengeRandomSize {
		t.Fatal("los nonces deben tener 32 bytes")
	}
}

// Comprueba que un desafío desaparezca después del primer consumo.
func TestAuthChallengeCanOnlyBeConsumedOnce(t *testing.T) {
	service := NewAuthChallengeService()
	id, nonce, expiresAt, err := service.Create(42)
	if err != nil {
		t.Fatalf("no se pudo crear el desafío: %v", err)
	}

	challenge, err := service.Consume(id)
	if err != nil {
		t.Fatalf("no se pudo consumir el desafío: %v", err)
	}

	if challenge.UserID != 42 || !bytes.Equal(challenge.Nonce, nonce) {
		t.Fatal("el desafío consumido no coincide con el creado")
	}
	if !challenge.ExpiresAt.Equal(expiresAt) {
		t.Fatal("la caducidad consumida no coincide con la creada")
	}

	if _, err := service.Consume(id); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatal("el segundo consumo debería rechazarse")
	}
}

// Comprueba que un desafío caducado no pueda consumirse.
func TestExpiredAuthChallengeIsRejected(t *testing.T) {
	service := NewAuthChallengeService()
	currentTime := time.Date(2026, time.October, 27, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return currentTime }

	id, _, _, err := service.Create(7)
	if err != nil {
		t.Fatalf("no se pudo crear el desafío: %v", err)
	}

	currentTime = currentTime.Add(challengeTTL)
	if _, err := service.Consume(id); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatal("un desafío caducado debería rechazarse")
	}
}
