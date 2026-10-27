package services

import (
	"os"
	"path/filepath"
	"testing"
)

// Comprueba que la identidad se genere una vez y se recupere con permisos seguros.
func TestServerKeyIsGeneratedAndReused(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys", "server_private.pem")

	generatedKey, err := LoadOrCreateServerKey(keyPath)
	if err != nil {
		t.Fatalf("no se pudo generar la clave del servidor: %v", err)
	}
	if generatedKey.N.BitLen() != serverKeySize {
		t.Fatalf("la clave debería tener %d bits", serverKeySize)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("no se pudo consultar el fichero generado: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("los permisos deberían ser 0600, se obtuvo %o", info.Mode().Perm())
	}

	loadedKey, err := LoadOrCreateServerKey(keyPath)
	if err != nil {
		t.Fatalf("no se pudo recargar la clave del servidor: %v", err)
	}
	if generatedKey.N.Cmp(loadedKey.N) != 0 || generatedKey.D.Cmp(loadedKey.D) != 0 {
		t.Fatal("la clave recargada debería coincidir con la generada")
	}
}
