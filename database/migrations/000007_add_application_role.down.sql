-- Elimina el rol de la aplicación. El backend tendrá que volver a conectarse
-- con el propietario de las tablas.

BEGIN;

REVOKE ALL
    ON users, accounts, account_users, transactions, documents, document_access,
       account_audit_events, document_audit_events
    FROM securitybank_app;

DROP ROLE securitybank_app;

COMMIT;
