BEGIN;

DROP TRIGGER IF EXISTS transaction_audit_events_no_truncate ON transaction_audit_events;
DROP TRIGGER IF EXISTS transaction_audit_events_append_only ON transaction_audit_events;
DROP TABLE IF EXISTS transaction_audit_events;

ALTER TABLE transactions
    DROP CONSTRAINT IF EXISTS transactions_idempotency_key,
    DROP CONSTRAINT IF EXISTS transactions_reference_key,
    DROP COLUMN IF EXISTS integrity_hmac,
    DROP COLUMN IF EXISTS idempotency_key,
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS reference;

COMMIT;

