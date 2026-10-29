-- Deja de auditar la emisión de certificados de titularidad.
-- ATENCIÓN: borra los eventos de emisión ya registrados.

BEGIN;

DELETE FROM account_audit_events WHERE action = 'ISSUE_CERTIFICATE';

ALTER TABLE account_audit_events
    DROP CONSTRAINT account_audit_events_certificate_check,
    DROP COLUMN certificate_id,
    DROP CONSTRAINT account_audit_events_action_check,
    ADD CONSTRAINT account_audit_events_action_check CHECK (action IN ('CREATE', 'CLOSE'));

COMMIT;
