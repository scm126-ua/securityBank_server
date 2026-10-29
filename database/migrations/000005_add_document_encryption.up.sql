-- =============================================================================
-- SecurityBank - Migración 000005: documentos cifrados de extremo a extremo
-- =============================================================================
--
-- El cliente cifra cada documento con una clave AES-256-GCM aleatoria y propia,
-- protege esa clave con RSA-OAEP (clave pública del usuario) y firma con
-- RSA-PSS un manifiesto de los datos cifrados. El servidor solo almacena datos
-- cifrados y comprueba la firma: nunca ve el contenido ni el nombre del archivo.
--
-- Las columnas nuevas son NOT NULL, así que la migración solo se aplica sobre
-- una tabla documents vacía (hasta ahora ningún endpoint escribía en ella).
-- =============================================================================

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM documents) THEN
        RAISE EXCEPTION 'La tabla documents contiene datos con un formato anterior: vacíala antes de migrar';
    END IF;
END
$$;

-- -----------------------------------------------------------------------------
-- 1. documents: formato cifrado versionado
-- -----------------------------------------------------------------------------
ALTER TABLE documents
    ADD COLUMN public_id          UUID     NOT NULL,
    ADD COLUMN format_version     SMALLINT NOT NULL,
    ADD COLUMN encrypted_metadata BYTEA    NOT NULL,
    ADD COLUMN metadata_nonce     BYTEA    NOT NULL,
    ADD COLUMN key_commitment     BYTEA    NOT NULL,
    ADD COLUMN signature          BYTEA    NOT NULL,
    ADD CONSTRAINT documents_public_id_key UNIQUE (public_id),
    ADD CONSTRAINT documents_format_version_check CHECK (format_version >= 1),
    -- 10 MiB de contenido (con relleno) + 16 bytes del tag GCM.
    ADD CONSTRAINT documents_encrypted_content_size_check CHECK (octet_length(encrypted_content) <= 10485776),
    ADD CONSTRAINT documents_encrypted_metadata_check CHECK (octet_length(encrypted_metadata) BETWEEN 17 AND 8192),
    ADD CONSTRAINT documents_metadata_nonce_check CHECK (octet_length(metadata_nonce) = 12),
    ADD CONSTRAINT documents_nonces_distinct_check CHECK (nonce <> metadata_nonce),
    ADD CONSTRAINT documents_key_commitment_check CHECK (octet_length(key_commitment) = 32),
    -- Firma RSA-PSS con una clave RSA-3072.
    ADD CONSTRAINT documents_signature_check CHECK (octet_length(signature) = 384);

COMMENT ON COLUMN documents.public_id          IS 'Identificador aleatorio (UUID v4) generado por el cliente. Es el único identificador expuesto en la API y forma parte de los datos autenticados.';
COMMENT ON COLUMN documents.format_version     IS 'Versión del formato criptográfico del documento.';
COMMENT ON COLUMN documents.nonce              IS 'Nonce (IV) de 12 bytes del contenido cifrado con AES-256-GCM.';
COMMENT ON COLUMN documents.encrypted_metadata IS 'Nombre, tipo MIME, tamaño real y SHA-256 del original, cifrados con la misma clave AES y rellenados a un tamaño fijo.';
COMMENT ON COLUMN documents.metadata_nonce     IS 'Nonce (IV) de 12 bytes de los metadatos. Nunca puede coincidir con el del contenido.';
COMMENT ON COLUMN documents.key_commitment     IS 'SHA-256 que compromete la clave AES del documento: detecta claves envueltas sustituidas.';
COMMENT ON COLUMN documents.signature          IS 'Firma RSA-PSS-SHA256 del propietario sobre el manifiesto del documento cifrado.';

-- -----------------------------------------------------------------------------
-- 2. document_access: preparada para permisos y compartición
-- -----------------------------------------------------------------------------
-- OWNER: puede descargar, compartir y eliminar. Siempre existe y no se revoca.
-- SHARE: puede descargar y volver a compartir con permiso READ (futuro).
-- READ:  solo puede descargar (futuro).
ALTER TABLE document_access
    ADD COLUMN key_algorithm VARCHAR(30) NOT NULL DEFAULT 'RSA-OAEP-3072-SHA256',
    ADD COLUMN granted_by    BIGINT      NOT NULL REFERENCES users (id),
    ADD COLUMN granted_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN revoked_at    TIMESTAMPTZ,
    ADD CONSTRAINT document_access_key_algorithm_check CHECK (key_algorithm IN ('RSA-OAEP-3072-SHA256')),
    ADD CONSTRAINT document_access_encrypted_key_size_check CHECK (
        key_algorithm <> 'RSA-OAEP-3072-SHA256' OR octet_length(encrypted_aes_key) = 384
    ),
    ADD CONSTRAINT document_access_revocation_check CHECK (revoked = (revoked_at IS NOT NULL)),
    ADD CONSTRAINT document_access_owner_not_revoked_check CHECK (NOT (permission = 'OWNER' AND revoked));

COMMENT ON COLUMN document_access.key_algorithm IS 'Algoritmo con el que se ha envuelto la clave AES. Permite cambiar de algoritmo en el futuro.';
COMMENT ON COLUMN document_access.granted_by    IS 'Usuario que concedió el acceso (el propietario en su propio registro).';
COMMENT ON COLUMN document_access.revoked_at    IS 'Fecha de revocación. Revocar no borra la clave ya entregada: para impedir el acceso futuro hay que volver a cifrar con una clave nueva.';

-- -----------------------------------------------------------------------------
-- 3. document_audit_events: auditoría append-only
-- -----------------------------------------------------------------------------
CREATE TABLE document_audit_events (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT      NOT NULL REFERENCES users (id),
    document_id UUID,
    action      VARCHAR(20) NOT NULL CHECK (action IN ('UPLOAD', 'DOWNLOAD', 'DELETE', 'SHARE', 'REVOKE')),
    result      VARCHAR(20) NOT NULL CHECK (result IN ('SUCCESS', 'DENIED', 'ERROR')),
    reason      VARCHAR(100),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT document_audit_events_reason_check CHECK (
        (result = 'SUCCESS' AND reason IS NULL)
        OR
        (result IN ('DENIED', 'ERROR') AND reason IS NOT NULL)
    )
);

CREATE INDEX document_audit_events_user_created_idx
    ON document_audit_events (user_id, created_at DESC);

CREATE INDEX document_audit_events_document_created_idx
    ON document_audit_events (document_id, created_at DESC)
    WHERE document_id IS NOT NULL;

COMMENT ON TABLE  document_audit_events             IS 'Eventos append-only de subida, descarga y eliminación de documentos. No se pueden modificar ni borrar.';
COMMENT ON COLUMN document_audit_events.document_id IS 'public_id del documento afectado o solicitado. Sin clave foránea para registrar intentos sobre documentos inexistentes o eliminados.';
COMMENT ON COLUMN document_audit_events.reason      IS 'Código técnico del rechazo o error, sin información sensible.';

-- Impide modificar o borrar eventos incluso si la aplicación tiene un fallo o
-- sufre una inyección SQL. El propietario de la tabla podría desactivar el
-- trigger: en producción la aplicación debería usar un rol sin ese privilegio.
CREATE FUNCTION reject_audit_event_changes() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Los eventos de auditoría no se pueden modificar ni borrar (tabla %)', TG_TABLE_NAME;
END
$$;

CREATE TRIGGER document_audit_events_append_only
    BEFORE UPDATE OR DELETE ON document_audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_event_changes();

CREATE TRIGGER document_audit_events_no_truncate
    BEFORE TRUNCATE ON document_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_changes();

COMMIT;
