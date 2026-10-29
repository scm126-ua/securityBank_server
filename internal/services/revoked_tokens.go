package services

import (
	"sync"
	"time"
)

// Sesiones cerradas antes de caducar. Se guardan en memoria, como los desafíos
// de login: si el backend se reinicia, los tokens siguen caducando en una hora.
type RevokedTokens struct {
	mu     sync.Mutex
	tokens map[string]time.Time
}

func NewRevokedTokens() *RevokedTokens {
	return &RevokedTokens{tokens: make(map[string]time.Time)}
}

// Revoca un token hasta su caducidad y descarta los que ya han caducado.
func (r *RevokedTokens) Revoke(tokenID string, expiresAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for id, expiration := range r.tokens {
		if !now.Before(expiration) {
			delete(r.tokens, id)
		}
	}
	r.tokens[tokenID] = expiresAt
}

// Indica si el token pertenece a una sesión cerrada.
func (r *RevokedTokens) IsRevoked(tokenID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, revoked := r.tokens[tokenID]
	return revoked
}
