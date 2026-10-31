BEGIN;

-- ADVERTENCIA: los valores cifrados no se pueden convertir a texto sin la
-- clave DATA_ENCRYPTION_KEY. Este down solo funciona si las filas siguen en
-- texto plano (por ejemplo, inmediatamente después del up y antes de arrancar
-- el backend). Si ya están cifradas, restaura una copia de seguridad.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_dni_hash_format_check;
DROP INDEX IF EXISTS users_dni_hash_key;
ALTER TABLE users DROP COLUMN IF EXISTS dni_hash;
ALTER TABLE users ALTER COLUMN dni TYPE VARCHAR(20) USING convert_from(dni, 'UTF8');
ALTER TABLE users ADD CONSTRAINT users_dni_key UNIQUE (dni);

ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_iban_hash_format_check;
DROP INDEX IF EXISTS accounts_iban_hash_key;
ALTER TABLE accounts DROP COLUMN IF EXISTS iban_hash;
ALTER TABLE accounts ALTER COLUMN iban TYPE VARCHAR(34) USING convert_from(iban, 'UTF8');
ALTER TABLE accounts ADD CONSTRAINT accounts_iban_key UNIQUE (iban);

COMMIT;
