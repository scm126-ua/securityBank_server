-- Elimina la firma de certificación de las claves públicas del usuario.

BEGIN;

ALTER TABLE users
    DROP COLUMN public_keys_signature;

COMMIT;
