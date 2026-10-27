package services

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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

// Comprueba que la identidad publicada contiene la clave y la huella esperadas.
func TestServerPublicIdentityCanBeImported(t *testing.T) {
	privateKey, err := LoadOrCreateServerKey(filepath.Join(t.TempDir(), "server_private.pem"))
	if err != nil {
		t.Fatalf("no se pudo preparar la clave del servidor: %v", err)
	}

	identity, err := ExportServerPublicIdentity(privateKey)
	if err != nil {
		t.Fatalf("no se pudo exportar la identidad pública: %v", err)
	}

	encodedPublicKey, err := base64.StdEncoding.Strict().DecodeString(identity.PublicKey)
	if err != nil {
		t.Fatalf("la clave pública no está codificada correctamente: %v", err)
	}

	parsedPublicKey, err := x509.ParsePKIXPublicKey(encodedPublicKey)
	if err != nil {
		t.Fatalf("la clave pública no tiene formato SPKI: %v", err)
	}
	parsedRSAKey, ok := parsedPublicKey.(*rsa.PublicKey)
	if !ok || parsedRSAKey.N.Cmp(privateKey.N) != 0 || parsedRSAKey.E != privateKey.E {
		t.Fatal("la identidad no contiene la clave pública del servidor")
	}

	expectedFingerprint := sha256.Sum256(encodedPublicKey)
	if identity.FingerprintSHA256 != hex.EncodeToString(expectedFingerprint[:]) {
		t.Fatal("la huella publicada no corresponde a la clave pública")
	}
}
