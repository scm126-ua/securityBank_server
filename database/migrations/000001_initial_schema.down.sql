-- =============================================================================
-- SecurityBank - Deshace la migración 000001 (esquema inicial)
-- =============================================================================
--
-- ATENCIÓN: borra las seis tablas y TODOS sus datos. Úsalo solo en desarrollo.
-- Las tablas se borran en orden inverso a sus claves foráneas.
-- =============================================================================

BEGIN;

DROP TABLE document_access;
DROP TABLE documents;
DROP TABLE transactions;
DROP TABLE account_users;
DROP TABLE accounts;
DROP TABLE users;

COMMIT;
