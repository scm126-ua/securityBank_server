-- Deshace la migración 000005 (documentos cifrados de extremo a extremo).
--
-- ATENCIÓN: borra la auditoría de documentos y las columnas criptográficas.
-- Los documentos que queden en la tabla dejan de poder descifrarse.

BEGIN;

DROP TABLE document_audit_events;
DROP FUNCTION reject_audit_event_changes();

ALTER TABLE document_access
    DROP CONSTRAINT document_access_owner_not_revoked_check,
    DROP CONSTRAINT document_access_revocation_check,
    DROP CONSTRAINT document_access_encrypted_key_size_check,
    DROP CONSTRAINT document_access_key_algorithm_check,
    DROP COLUMN revoked_at,
    DROP COLUMN granted_at,
    DROP COLUMN granted_by,
    DROP COLUMN key_algorithm;

ALTER TABLE documents
    DROP CONSTRAINT documents_signature_check,
    DROP CONSTRAINT documents_key_commitment_check,
    DROP CONSTRAINT documents_nonces_distinct_check,
    DROP CONSTRAINT documents_metadata_nonce_check,
    DROP CONSTRAINT documents_encrypted_metadata_check,
    DROP CONSTRAINT documents_encrypted_content_size_check,
    DROP CONSTRAINT documents_format_version_check,
    DROP CONSTRAINT documents_public_id_key,
    DROP COLUMN signature,
    DROP COLUMN key_commitment,
    DROP COLUMN metadata_nonce,
    DROP COLUMN encrypted_metadata,
    DROP COLUMN format_version,
    DROP COLUMN public_id;

COMMIT;
