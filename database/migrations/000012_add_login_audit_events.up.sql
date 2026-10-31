-- Auditoría append-only de los intentos de inicio de sesión.
--
-- No se guardan credenciales: solo el email intentado, el origen de la
-- petición y el resultado. El estado ACCOUNT_NOT_FOUND permite distinguir un
-- email inexistente de unas credenciales incorrectas.

BEGIN;

CREATE TABLE login_audit_events (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- NULL cuando el email no corresponde a ningún usuario registrado.
    user_id    BIGINT REFERENCES users (id),
    email      VARCHAR(320) NOT NULL,
    ip_address VARCHAR(45)  NOT NULL DEFAULT '',
    user_agent VARCHAR(512) NOT NULL DEFAULT '',
    result     VARCHAR(20)  NOT NULL CHECK (result IN ('SUCCESSFUL', 'FAILED', 'ACCOUNT_NOT_FOUND')),
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Consultas habituales: intentos recientes de una cuenta y actividad global.
CREATE INDEX login_audit_events_email_created_idx
    ON login_audit_events (lower(email), created_at DESC);

CREATE INDEX login_audit_events_created_idx
    ON login_audit_events (created_at DESC);

-- Misma inmutabilidad que el resto de auditorías.
CREATE TRIGGER login_audit_events_append_only
    BEFORE UPDATE OR DELETE ON login_audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_event_changes();

CREATE TRIGGER login_audit_events_no_truncate
    BEFORE TRUNCATE ON login_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_changes();

-- El backend solo puede consultar y añadir eventos.
GRANT SELECT, INSERT ON login_audit_events TO securitybank_app;

COMMENT ON TABLE login_audit_events IS 'Eventos append-only de intentos de inicio de sesión.';
COMMENT ON COLUMN login_audit_events.user_id IS 'Usuario encontrado para el email intentado; NULL si la cuenta no existe.';
COMMENT ON COLUMN login_audit_events.email IS 'Email normalizado del intento. No se guardan contraseñas ni claves de autenticación.';
COMMENT ON COLUMN login_audit_events.ip_address IS 'IP de origen de la petición (IPv4 o IPv6).';
COMMENT ON COLUMN login_audit_events.user_agent IS 'Cabecera User-Agent de la petición, truncada a 512 caracteres.';
COMMENT ON COLUMN login_audit_events.result IS 'SUCCESSFUL, FAILED o ACCOUNT_NOT_FOUND.';
COMMENT ON COLUMN login_audit_events.created_at IS 'Fecha y hora del intento de inicio de sesión.';

COMMIT;
