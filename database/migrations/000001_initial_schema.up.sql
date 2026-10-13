-- =============================================================================
-- SecurityBank - Migración 000001: esquema inicial (PostgreSQL 17)
-- =============================================================================
--
-- Las migraciones de database/migrations/ son la fuente de verdad del esquema:
-- el backend NO usa AutoMigrate de GORM. Las aplica golang-migrate (servicio
-- "migrate" de compose.yaml) en cada "docker compose up". Ver README.md.
--
-- No modifiques esta migración: cualquier cambio del esquema va en una
-- migración nueva (000002_..., 000003_...).
--
-- Todo el script se ejecuta en una única transacción: si algo falla no se
-- aplica ningún cambio.
--
-- Claves foráneas: se usa el comportamiento por defecto (NO ACTION), es decir,
-- no se puede borrar un usuario o una cuenta que tenga datos relacionados.
-- En un banco las cuentas se cierran (status = 'CLOSED'), no se borran.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. users
-- -----------------------------------------------------------------------------
CREATE TABLE users (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name               VARCHAR(100) NOT NULL,
    dni                VARCHAR(20)  NOT NULL UNIQUE,
    email              VARCHAR(150) NOT NULL UNIQUE,
    password_hash      TEXT         NOT NULL,
    salt               TEXT         NOT NULL,
    role               VARCHAR(20)  NOT NULL CHECK (role IN ('CLIENT', 'ADMIN')),
    public_key         TEXT,
    signing_public_key TEXT,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE  users                    IS 'Usuarios del banco. Solo se almacenan claves públicas; nunca claves privadas sin cifrar.';
COMMENT ON COLUMN users.password_hash      IS 'Hash de la contraseña. La contraseña nunca se guarda en texto plano.';
COMMENT ON COLUMN users.salt               IS 'Sal aleatoria usada al calcular password_hash.';
COMMENT ON COLUMN users.public_key         IS 'Clave pública para cifrar (p. ej. claves AES de documentos). NULL hasta completar el registro criptográfico.';
COMMENT ON COLUMN users.signing_public_key IS 'Clave pública para verificar firmas digitales del usuario.';

-- -----------------------------------------------------------------------------
-- 2. accounts
-- -----------------------------------------------------------------------------
CREATE TABLE accounts (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    iban       VARCHAR(34)   NOT NULL UNIQUE,
    balance    NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (balance >= 0),
    status     VARCHAR(20)   NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'CLOSED')),
    created_at TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE  accounts         IS 'Cuentas bancarias simuladas.';
COMMENT ON COLUMN accounts.balance IS 'Saldo en euros. NUMERIC (nunca FLOAT) para evitar errores de redondeo. No puede ser negativo.';

-- -----------------------------------------------------------------------------
-- 3. account_users  (relación N:M entre users y accounts)
-- -----------------------------------------------------------------------------
CREATE TABLE account_users (
    user_id    BIGINT      NOT NULL REFERENCES users (id),
    account_id BIGINT      NOT NULL REFERENCES accounts (id),
    role       VARCHAR(20) NOT NULL CHECK (role IN ('OWNER', 'CO_OWNER', 'AUTHORIZED')),

    PRIMARY KEY (user_id, account_id)
);

-- La primary key (user_id, account_id) ya sirve para buscar por user_id;
-- este índice permite buscar los usuarios de una cuenta.
CREATE INDEX account_users_account_id_idx ON account_users (account_id);

-- Cada cuenta tiene como máximo un OWNER. Los demás titulares son CO_OWNER.
CREATE UNIQUE INDEX account_users_one_owner_idx ON account_users (account_id) WHERE role = 'OWNER';

COMMENT ON TABLE account_users IS 'Relación N:M entre usuarios y cuentas, con el rol del usuario en cada cuenta.';

-- -----------------------------------------------------------------------------
-- 4. transactions
-- -----------------------------------------------------------------------------
CREATE TABLE transactions (
    id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_account_id      BIGINT        REFERENCES accounts (id),
    destination_account_id BIGINT        REFERENCES accounts (id),
    type                   VARCHAR(20)   NOT NULL CHECK (type IN ('DEPOSIT', 'WITHDRAWAL', 'TRANSFER')),
    amount                 NUMERIC(18,2) NOT NULL CHECK (amount > 0),
    created_at             TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Las cuentas implicadas dependen del tipo de movimiento.
    CONSTRAINT transactions_accounts_by_type_check CHECK (
        (type = 'DEPOSIT'
            AND source_account_id IS NULL
            AND destination_account_id IS NOT NULL)
        OR
        (type = 'WITHDRAWAL'
            AND source_account_id IS NOT NULL
            AND destination_account_id IS NULL)
        OR
        (type = 'TRANSFER'
            AND source_account_id IS NOT NULL
            AND destination_account_id IS NOT NULL
            AND source_account_id <> destination_account_id)
    )
);

CREATE INDEX transactions_source_account_id_idx      ON transactions (source_account_id);
CREATE INDEX transactions_destination_account_id_idx ON transactions (destination_account_id);

COMMENT ON TABLE  transactions        IS 'Movimientos: ingresos (DEPOSIT), retiradas (WITHDRAWAL) y transferencias (TRANSFER).';
COMMENT ON COLUMN transactions.amount IS 'Importe en euros, siempre positivo. El tipo indica el sentido del movimiento.';

-- -----------------------------------------------------------------------------
-- 5. documents
-- -----------------------------------------------------------------------------
CREATE TABLE documents (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id          BIGINT      NOT NULL REFERENCES users (id),
    type              VARCHAR(30) NOT NULL CHECK (type IN ('STATEMENT', 'TRANSACTION_RECEIPT', 'OWNERSHIP_CERTIFICATE', 'PERSONAL')),
    -- AES-256-GCM: el ciphertext lleva el tag de autenticación de 16 bytes al final.
    encrypted_content BYTEA       NOT NULL CHECK (octet_length(encrypted_content) >= 16),
    -- Nonce (IV) de 12 bytes, el tamaño estándar para AES-GCM.
    nonce             BYTEA       NOT NULL CHECK (octet_length(nonce) = 12),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX documents_owner_id_idx ON documents (owner_id);

COMMENT ON TABLE  documents                   IS 'Documentos cifrados en el cliente con AES-256-GCM. El servidor nunca ve el contenido en claro.';
COMMENT ON COLUMN documents.encrypted_content IS 'Formato: ciphertext || tag GCM (16 bytes al final).';
COMMENT ON COLUMN documents.nonce             IS 'Nonce (IV) de 12 bytes usado en el cifrado AES-256-GCM. Debe ser único para cada cifrado.';

-- -----------------------------------------------------------------------------
-- 6. document_access
-- -----------------------------------------------------------------------------
CREATE TABLE document_access (
    -- Si se borra un documento, se borran también sus copias de la clave AES.
    document_id       BIGINT      NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
    user_id           BIGINT      NOT NULL REFERENCES users (id),
    encrypted_aes_key BYTEA       NOT NULL,
    permission        VARCHAR(20) NOT NULL DEFAULT 'OWNER' CHECK (permission IN ('OWNER', 'READ', 'SHARE')),
    revoked           BOOLEAN     NOT NULL DEFAULT FALSE,

    PRIMARY KEY (document_id, user_id)
);

-- La primary key (document_id, user_id) ya sirve para buscar por document_id;
-- este índice permite buscar los documentos accesibles por un usuario.
CREATE INDEX document_access_user_id_idx ON document_access (user_id);

-- Cada documento tiene como máximo un registro OWNER (el de su propietario).
CREATE UNIQUE INDEX document_access_one_owner_idx ON document_access (document_id) WHERE permission = 'OWNER';

COMMENT ON TABLE  document_access                   IS 'Copia de la clave AES de cada documento cifrada con la clave pública de cada usuario autorizado.';
COMMENT ON COLUMN document_access.encrypted_aes_key IS 'Clave AES-256 del documento cifrada con users.public_key del usuario.';
COMMENT ON COLUMN document_access.revoked           IS 'TRUE cuando se ha revocado el acceso del usuario al documento.';

COMMIT;
