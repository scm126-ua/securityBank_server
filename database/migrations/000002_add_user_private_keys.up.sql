-- Añade el paquete cifrado que permite recuperar las claves privadas del usuario.

BEGIN;

ALTER TABLE users
    ADD COLUMN encrypted_private_keys  BYTEA,
    ADD COLUMN private_keys_salt       BYTEA,
    ADD COLUMN private_keys_nonce      BYTEA,
    ADD COLUMN private_keys_iterations INTEGER,
    ADD COLUMN private_keys_version    SMALLINT,
    ADD CONSTRAINT users_private_keys_complete_check CHECK (
        num_nonnulls(
            encrypted_private_keys,
            private_keys_salt,
            private_keys_nonce,
            private_keys_iterations,
            private_keys_version
        ) IN (0, 5)
    ),
    ADD CONSTRAINT users_private_keys_ciphertext_check CHECK (
        encrypted_private_keys IS NULL OR octet_length(encrypted_private_keys) >= 16
    ),
    ADD CONSTRAINT users_private_keys_salt_check CHECK (
        private_keys_salt IS NULL OR octet_length(private_keys_salt) = 16
    ),
    ADD CONSTRAINT users_private_keys_nonce_check CHECK (
        private_keys_nonce IS NULL OR octet_length(private_keys_nonce) = 12
    ),
    ADD CONSTRAINT users_private_keys_iterations_check CHECK (
        private_keys_iterations IS NULL OR private_keys_iterations >= 100000
    ),
    ADD CONSTRAINT users_private_keys_version_check CHECK (
        private_keys_version IS NULL OR private_keys_version >= 1
    );

COMMENT ON COLUMN users.encrypted_private_keys IS 'Claves privadas del usuario cifradas en el cliente con AES-256-GCM.';
COMMENT ON COLUMN users.private_keys_salt IS 'Sal de 16 bytes usada por PBKDF2 para proteger las claves privadas.';
COMMENT ON COLUMN users.private_keys_nonce IS 'Nonce de 12 bytes usado por AES-GCM para proteger las claves privadas.';
COMMENT ON COLUMN users.private_keys_iterations IS 'Número de iteraciones PBKDF2 usado para derivar la clave de protección.';
COMMENT ON COLUMN users.private_keys_version IS 'Versión del formato del paquete de claves privadas cifradas.';

COMMIT;
