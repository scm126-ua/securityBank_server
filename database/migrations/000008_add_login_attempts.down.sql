-- Elimina los campos de control de intentos fallidos de inicio de sesión.

BEGIN;

ALTER TABLE users
    DROP COLUMN IF EXISTS failed_login_attempts,
    DROP COLUMN IF EXISTS last_failed_login_attempt,
    DROP COLUMN IF EXISTS locked_until;

COMMIT;