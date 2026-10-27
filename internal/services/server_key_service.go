package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const serverKeySize = 3072

// Carga la identidad del servidor o crea una nueva cuando todavía no existe.
func LoadOrCreateServerKey(path string) (*rsa.PrivateKey, error) {
	privateKey, err := loadServerKey(path)
	if err == nil {
		return privateKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("no se pudo crear el directorio de claves: %w", err)
	}

	privateKey, err = rsa.GenerateKey(rand.Reader, serverKeySize)
	if err != nil {
		return nil, fmt.Errorf("no se pudo generar la clave del servidor: %w", err)
	}

	if err := writeServerKey(path, privateKey); err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadServerKey(path)
		}
		return nil, err
	}

	return privateKey, nil
}

// Lee y valida una clave privada RSA-3072 codificada en PEM.
func loadServerKey(path string) (*rsa.PrivateKey, error) {
	encodedKey, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("la clave del servidor no tiene un formato PEM válido")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("no se pudo interpretar la clave del servidor: %w", err)
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok || privateKey.N.BitLen() != serverKeySize || privateKey.E != 65537 {
		return nil, errors.New("la clave del servidor debe ser RSA-3072")
	}
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("la clave del servidor no es válida: %w", err)
	}

	if err := os.Chmod(path, 0600); err != nil {
		return nil, fmt.Errorf("no se pudieron proteger los permisos de la clave: %w", err)
	}

	return privateKey, nil
}

// Guarda la clave privada sin sobrescribir una identidad ya existente.
func writeServerKey(path string, privateKey *rsa.PrivateKey) error {
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("no se pudo codificar la clave del servidor: %w", err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}

	completed := false
	defer func() {
		if !completed {
			_ = os.Remove(path)
		}
	}()

	encodedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encodedKey,
	})
	if _, err := file.Write(encodedPEM); err != nil {
		_ = file.Close()
		return fmt.Errorf("no se pudo escribir la clave del servidor: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("no se pudo guardar la clave del servidor: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("no se pudo cerrar la clave del servidor: %w", err)
	}

	completed = true
	return nil
}
