-- Elimina el registro de auditoría de operaciones sobre cuentas.

BEGIN;

DROP TABLE account_audit_events;

COMMIT;
