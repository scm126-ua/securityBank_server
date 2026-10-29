-- Audita la emisión de certificados de titularidad firmados por el banco.

BEGIN;

ALTER TABLE account_audit_events
    DROP CONSTRAINT account_audit_events_action_check,
    ADD CONSTRAINT account_audit_events_action_check CHECK (action IN ('CREATE', 'CLOSE', 'ISSUE_CERTIFICATE')),
    ADD COLUMN certificate_id VARCHAR(32),
    ADD CONSTRAINT account_audit_events_certificate_check CHECK (
        (action = 'ISSUE_CERTIFICATE' AND result = 'SUCCESS') = (certificate_id IS NOT NULL)
    );

COMMENT ON COLUMN account_audit_events.certificate_id IS 'Identificador del certificado de titularidad emitido. Permite comprobar si el banco emitió un certificado concreto.';

COMMIT;
