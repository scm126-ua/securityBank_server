-- =============================================================================
-- SecurityBank - Migración 000009: transacciones seguras, idempotencia y auditoría
-- =============================================================================

BEGIN;

-- 1. Enriquecer la tabla transactions existente
ALTER TABLE transactions
    ADD COLUMN reference UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN description VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN idempotency_key VARCHAR(64),
    ADD COLUMN integrity_hmac VARCHAR(64) NOT NULL DEFAULT '',
    ADD CONSTRAINT transactions_reference_key UNIQUE (reference),
    ADD CONSTRAINT transactions_idempotency_key UNIQUE (idempotency_key);

CREATE INDEX transactions_reference_idx ON transactions (reference);
CREATE INDEX transactions_created_at_idx ON transactions (created_at DESC);

COMMENT ON COLUMN transactions.reference IS 'Identificador público UUID v4 para trazabilidad y justificantes.';
COMMENT ON COLUMN transactions.idempotency_key IS 'Clave única enviada por el cliente para evitar pagos duplicados.';
COMMENT ON COLUMN transactions.integrity_hmac IS 'HMAC-SHA256 calculado por el servidor para verificar la integridad del movimiento en reposo.';

-- 2. Tabla de auditoría append-only para movimientos bancarios
CREATE TABLE transaction_audit_events (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id               BIGINT NOT NULL REFERENCES users (id),
    account_id            BIGINT CHECK (account_id IS NULL OR account_id > 0),
    transaction_reference UUID,
    action                VARCHAR(20) NOT NULL CHECK (action IN ('DEPOSIT', 'WITHDRAWAL', 'TRANSFER')),
    result                VARCHAR(20) NOT NULL CHECK (result IN ('SUCCESS', 'DENIED', 'ERROR')),
    reason                VARCHAR(100),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT transaction_audit_events_reason_check CHECK (
        (result = 'SUCCESS' AND reason IS NULL)
        OR
        (result IN ('DENIED', 'ERROR') AND reason IS NOT NULL)
    )
);

CREATE INDEX transaction_audit_events_user_idx ON transaction_audit_events (user_id, created_at DESC);
CREATE INDEX transaction_audit_events_account_idx ON transaction_audit_events (account_id, created_at DESC);

-- Triggers de inmutabilidad: impiden modificar (UPDATE), borrar (DELETE) o vaciar (TRUNCATE) la auditoría
CREATE TRIGGER transaction_audit_events_append_only
    BEFORE UPDATE OR DELETE ON transaction_audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_event_changes();

CREATE TRIGGER transaction_audit_events_no_truncate
    BEFORE TRUNCATE ON transaction_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_changes();

-- 3. Permisos de mínimos privilegios para el rol de la aplicación
GRANT SELECT, INSERT ON transaction_audit_events TO securitybank_app;

COMMIT;

