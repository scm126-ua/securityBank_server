-- Guarda la firma con la que el servidor certifica las claves públicas del usuario.

BEGIN;

ALTER TABLE users
    ADD COLUMN public_keys_signature TEXT,
    ADD CONSTRAINT users_public_keys_signature_length_check CHECK (
        public_keys_signature IS NULL OR char_length(public_keys_signature) = 512
    );

COMMENT ON COLUMN users.public_keys_signature IS 'Firma RSA-PSS del servidor sobre el correo y las dos claves públicas del usuario, codificada en Base64.';

COMMIT;
