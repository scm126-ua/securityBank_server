-- Registra los resultados de las operaciones sensibles realizadas sobre cuentas.

BEGIN;

CREATE TABLE account_audit_events (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users (id),
    account_id BIGINT      CHECK (account_id IS NULL OR account_id > 0),
    action     VARCHAR(20) NOT NULL CHECK (action IN ('CREATE', 'CLOSE')),
    result     VARCHAR(20) NOT NULL CHECK (result IN ('SUCCESS', 'DENIED', 'ERROR')),
    reason     VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT account_audit_events_reason_check CHECK (
        (result = 'SUCCESS' AND reason IS NULL)
        OR
        (result IN ('DENIED', 'ERROR') AND reason IS NOT NULL)
    )
);

CREATE INDEX account_audit_events_user_created_idx
    ON account_audit_events (user_id, created_at DESC);

CREATE INDEX account_audit_events_account_created_idx
    ON account_audit_events (account_id, created_at DESC)
    WHERE account_id IS NOT NULL;

COMMENT ON TABLE account_audit_events IS 'Eventos append-only de creación y cierre de cuentas bancarias.';
COMMENT ON COLUMN account_audit_events.user_id IS 'Usuario autenticado que solicitó la operación.';
COMMENT ON COLUMN account_audit_events.account_id IS 'Cuenta afectada o identificador solicitado. No tiene clave foránea para registrar intentos sobre cuentas inexistentes.';
COMMENT ON COLUMN account_audit_events.reason IS 'Código técnico del rechazo o error, sin información sensible.';

COMMIT;
