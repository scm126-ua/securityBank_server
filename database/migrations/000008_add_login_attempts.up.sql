
-- Añade campos para controlar los intentos fallidos de inicio de sesión.

BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_failed_login_attempt TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ NULL;

END;