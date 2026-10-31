BEGIN;

DROP TRIGGER IF EXISTS login_audit_events_no_truncate ON login_audit_events;
DROP TRIGGER IF EXISTS login_audit_events_append_only ON login_audit_events;
DROP TABLE IF EXISTS login_audit_events;

COMMIT;
