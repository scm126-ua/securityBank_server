BEGIN;

-- 1. users: cifrado del DNI con AES-256-GCM
-- La columna pasa a BYTEA: el backend guarda [versión(1)][nonce(12)][ciphertext][tag(16)].
-- El contenido existente (texto plano) se conserva como bytes y el backend lo
-- cifra al arrancar, porque la clave DATA_ENCRYPTION_KEY no está en PostgreSQL.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_dni_key;
ALTER TABLE users ADD COLUMN IF NOT EXISTS dni_hash VARCHAR(64);
ALTER TABLE users ALTER COLUMN dni TYPE BYTEA USING dni::bytea;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_dni_hash_format_check;
ALTER TABLE users ADD CONSTRAINT users_dni_hash_format_check
    CHECK (dni_hash IS NULL OR dni_hash ~ '^[0-9a-f]{64}$');
CREATE UNIQUE INDEX IF NOT EXISTS users_dni_hash_key ON users (dni_hash);

COMMENT ON COLUMN users.dni IS 'DNI del usuario cifrado en reposo con AES-256-GCM (sobre con versión y AAD).';
COMMENT ON COLUMN users.dni_hash IS 'Blind index HMAC-SHA256 del DNI para búsquedas y unicidad sin comprometer la confidencialidad.';

-- 2. accounts: cifrado del IBAN con AES-256-GCM
ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_iban_key;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS iban_hash VARCHAR(64);
ALTER TABLE accounts ALTER COLUMN iban TYPE BYTEA USING iban::bytea;
ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_iban_hash_format_check;
ALTER TABLE accounts ADD CONSTRAINT accounts_iban_hash_format_check
    CHECK (iban_hash IS NULL OR iban_hash ~ '^[0-9a-f]{64}$');
CREATE UNIQUE INDEX IF NOT EXISTS accounts_iban_hash_key ON accounts (iban_hash);

COMMENT ON COLUMN accounts.iban IS 'IBAN de la cuenta cifrado en reposo con AES-256-GCM (sobre con versión y AAD).';
COMMENT ON COLUMN accounts.iban_hash IS 'Blind index HMAC-SHA256 del IBAN para transferencias y búsquedas sin exponer el número de cuenta.';

COMMIT;
