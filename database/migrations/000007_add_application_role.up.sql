-- Crea el rol con privilegios mínimos con el que se conecta el backend. Las
-- migraciones siguen ejecutándose con el propietario de las tablas.
--
-- El rol se crea sin acceso: el servicio app-role de compose.yaml le asigna
-- la contraseña de APP_DB_PASSWORD, que nunca se sube a Git.
--
-- Cada tabla nueva necesita su GRANT en la migración que la crea.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securitybank_app') THEN
        CREATE ROLE securitybank_app NOLOGIN;
    END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE, DELETE
    ON users, accounts, account_users, transactions, documents, document_access
    TO securitybank_app;

-- La aplicación solo puede consultar y añadir eventos de auditoría. Como no es la
-- propietaria de las tablas, tampoco puede desactivar sus triggers ni cambiar el esquema.
GRANT SELECT, INSERT ON account_audit_events, document_audit_events TO securitybank_app;

COMMIT;
