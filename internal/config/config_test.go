package config

import "testing"

func TestLoadRequiresDataEncryptionKey(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost/db")
	t.Setenv("DATA_ENCRYPTION_KEY", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load debe fallar si falta DATA_ENCRYPTION_KEY")
	}

	t.Setenv("DATA_ENCRYPTION_KEY", "01234567890123456789012345678901")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load falló con una clave configurada: %v", err)
	}
	if cfg.DataEncryptionKey == "" {
		t.Fatal("DataEncryptionKey no se leyó de la variable de entorno")
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("DATA_ENCRYPTION_KEY", "01234567890123456789012345678901")

	if _, err := Load(); err == nil {
		t.Fatal("Load debe fallar si falta DATABASE_URL")
	}
}
