-- Elimina el paquete cifrado de claves privadas de los usuarios.

BEGIN;

ALTER TABLE users
    DROP COLUMN private_keys_version,
    DROP COLUMN private_keys_iterations,
    DROP COLUMN private_keys_nonce,
    DROP COLUMN private_keys_salt,
    DROP COLUMN encrypted_private_keys;

COMMIT;
