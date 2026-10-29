# securityBank_server

Backend de SecurityBank (Go + Gin + GORM) y entorno de desarrollo local con Docker Compose
(frontend Vue 3, backend Go y PostgreSQL 17).

## Requisitos previos

- **Docker Desktop** instalado y en ejecución.
- **Git**, con los dos repositorios clonados uno al lado del otro (ver estructura).
- **DBeaver** (opcional) para consultar la base de datos.
- Puertos libres en tu ordenador: **8443** (aplicación HTTPS) y **5432** (PostgreSQL).
  Si tienes PostgreSQL instalado en Windows, su servicio ocupa el 5432: detenlo o cambia
  `POSTGRES_HOST_PORT` en `.env` (ver más abajo).

No hace falta instalar Go ni Node: se ejecutan dentro de los contenedores.

## Estructura del proyecto

```
SecurityBank/
├── securityBank_client/
│   └── securityBank_client/          # Frontend Vue 3 + Vite
└── securityBank_server/              # Este repositorio
    ├── cmd/api/main.go               # Arranque: configuración, conexión a PostgreSQL y rutas
    ├── internal/
    │   ├── config/                   # Lectura de variables de entorno
    │   ├── database/                 # Conexión GORM, ping y comprobación de tablas
    │   ├── handlers/                 # Manejadores HTTP (salud, login, cuentas y documentos)
    │   ├── models/                   # Modelos GORM de las tablas
    │   ├── repositories/             # Consultas a la base de datos y control de acceso
    │   └── services/                 # Lógica de negocio y criptografía del servidor
    ├── middleware/                   # Autenticación JWT y cabeceras de seguridad de la API
    ├── database/migrations/          # Migraciones SQL: fuente de verdad de la base de datos
    ├── Caddyfile                     # Proxy HTTPS para el frontend y la API
    ├── compose.yaml                  # Servicios frontend, backend, proxy, db y migrate
    ├── Dockerfile                    # Imagen de desarrollo del backend (Go + Air)
    ├── .air.toml                     # Recarga automática del backend
    └── .env.example                  # Plantilla de variables de entorno
```

## Configurar `.env`

Copia la plantilla la primera vez (funciona en PowerShell y en Git Bash):

```sh
cp .env.example .env
```

| Variable             | Descripción                                                              |
|----------------------|--------------------------------------------------------------------------|
| `POSTGRES_DB`        | Nombre de la base de datos (`securitybank`)                              |
| `POSTGRES_USER`      | Usuario de PostgreSQL (`securitybank`)                                   |
| `POSTGRES_PASSWORD`  | Contraseña de PostgreSQL. Pon una propia, solo para desarrollo           |
| `POSTGRES_HOST_PORT` | Puerto de tu ordenador para DBeaver (`5432`; usa `5433` si está ocupado) |
| `APP_DB_PASSWORD`    | Contraseña del rol `securitybank_app` del backend. Distinta de la anterior |
| `MIGRATE_DATABASE_URL` | Conexión de las migraciones, con el propietario de las tablas          |
| `DATABASE_URL`       | Conexión del backend, con el rol `securitybank_app` de privilegios mínimos |
| `BACKEND_PORT`       | Puerto interno del backend (`8080`)                                      |
| `HTTPS_PORT`         | Puerto HTTPS público del proxy (`8443`)                                  |
| `CORS_ORIGIN`        | Origen del frontend permitido por CORS (`https://localhost:8443`)        |
| `SERVER_KEY_FINGERPRINT` | Huella de la clave del servidor que exige el frontend (opcional, ver logs del backend) |

- `.env` está excluido de Git: no subas nunca contraseñas ni credenciales reales.
- PostgreSQL solo aplica `POSTGRES_USER` y `POSTGRES_PASSWORD` la primera vez que crea el
  volumen. Si los cambias después, tienes que recrear el volumen (`docker compose down -v`,
  que **borra los datos**).

## Levantar Docker

```sh
docker compose up --build        # construye las imágenes y arranca (Ctrl+C para parar)
docker compose up -d --build     # lo mismo, en segundo plano
docker compose ps                # estado de los contenedores
```

| Servicio       | URL                                       |
|----------------|-------------------------------------------|
| Aplicación     | https://localhost:8443                    |
| Salud de la API | https://localhost:8443/api/health        |
| PostgreSQL     | localhost:5432                            |

Caddy genera un certificado local para el entorno de desarrollo. El navegador puede mostrar
un aviso de seguridad hasta que se confíe en su autoridad certificadora local.

Al guardar cambios, Vite recarga el frontend y Air recompila el backend automáticamente.

Orden de arranque: PostgreSQL → `migrate` (aplica las migraciones pendientes y termina) →
`app-role` (asigna la contraseña al rol de la aplicación y termina) → backend. Si una
migración falla, el backend no arranca. En `docker compose ps -a`, `migrate` y `app-role`
aparecen como `Exited (0)`: es lo normal.

El backend se conecta con el rol `securitybank_app`: puede leer y escribir los datos del
banco, pero solo consultar y añadir eventos de auditoría, y no puede cambiar el esquema ni
desactivar los *triggers*. Si un fallo o una inyección SQL comprometen la aplicación, la
auditoría sigue intacta.

Si cambias las dependencias del frontend (`package.json`), reinstálalas en el contenedor:

```sh
docker compose up -d --build -V frontend
```

## Detener Docker

```sh
docker compose stop      # para los contenedores sin eliminarlos
docker compose down      # para y elimina los contenedores; los datos de PostgreSQL se conservan
docker compose down -v   # para, elimina los contenedores y BORRA los datos de PostgreSQL
```

## Consultar los logs

```sh
docker compose logs -f              # todos los servicios, en tiempo real (Ctrl+C para salir)
docker compose logs -f backend      # solo el backend
docker compose logs --tail 50 db    # últimas 50 líneas de PostgreSQL
docker compose logs migrate         # migraciones aplicadas (o "no change")
```

Al arrancar, el backend indica si ha conectado con PostgreSQL y si existen todas las tablas:

```
conexión con PostgreSQL establecida
esquema de la base de datos comprobado: todas las tablas existen
```

## Comprobar los endpoints de salud

| Endpoint              | Qué comprueba                                    | Respuesta correcta (200)                            |
|-----------------------|--------------------------------------------------|-----------------------------------------------------|
| `GET /api/health`     | Que el backend está en marcha (no consulta la BD) | `{"status":"ok"}`                                   |
| `GET /api/health/db`  | Que PostgreSQL responde y existen todas las tablas | `{"database":"ok","schema":"ok","status":"ok"}`    |

Si PostgreSQL no responde, `/api/health/db` devuelve **503** con `"database":"unavailable"`;
si faltan tablas, **503** con `"schema":"incomplete"` (el detalle aparece en los logs del backend).

Desde el navegador o desde la terminal:

```sh
curl.exe -k https://localhost:8443/api/health       # PowerShell (curl a secas es otro comando)
curl.exe -k https://localhost:8443/api/health/db
curl --insecure https://localhost:8443/api/health/db # Git Bash
```

## Documentos cifrados de extremo a extremo

El navegador cifra cada documento antes de enviarlo. El servidor solo guarda datos cifrados:
nunca recibe la clave del documento ni su contenido, ni siquiera el nombre del archivo.
La lógica del cliente está en `src/services/documentCrypto.js` (repositorio del frontend).

### Diseño (formato versión 1)

| Medida                                                        | Para qué sirve                                                                                         |
|---------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| Clave AES-256-GCM aleatoria y distinta para cada documento    | Confidencialidad e integridad. Comprometer un documento no afecta a los demás                         |
| Clave envuelta con RSA-OAEP-3072-SHA256 (`users.public_key`)  | Solo quien tiene la clave privada la recupera. Se guarda en `document_access`, una fila por usuario     |
| AAD con el id, el propietario, el tipo y la versión           | El servidor no puede mover un cifrado a otro documento ni cambiar su tipo sin que falle GCM            |
| Metadatos cifrados (nombre, MIME, tamaño y SHA-256) a 2048 B  | El nombre del archivo tampoco queda en claro en la base de datos                                       |
| Relleno Padmé del contenido (mínimo 1 KiB)                    | Oculta el tamaño exacto con un sobrecoste máximo del 12 %                                              |
| Firma RSA-PSS del propietario sobre un manifiesto             | Autenticidad y no repudio. El servidor la comprueba al subir y al descargar                            |
| Compromiso SHA-256 de la clave AES                            | Detecta claves envueltas sustituidas y cifrados válidos con dos claves (*invisible salamanders*)       |
| SHA-256 del original                                          | Huella que el usuario puede comparar fuera de la aplicación                                            |
| UUID v4 aleatorio como identificador público                  | La API no expone identificadores secuenciales                                                          |

Comprobaciones al descargar:

1. **Servidor:** acceso vigente del usuario → certificado de las claves del propietario →
   firma del manifiesto. Si algo falla, no entrega el documento (500) y lo audita como
   `INTEGRITY_FAILURE`. Así detecta manipulaciones en la base de datos.
2. **Cliente** (no confía en el servidor): el documento recibido es el solicitado →
   el banco certifica al propietario → firma del propietario → compromiso de clave → tags
   GCM de metadatos y contenido → SHA-256 del original. Si algo falla, no se descarga nada.

Otras medidas:

- Solo se pueden subir documentos `PERSONAL` y `OWNERSHIP_CERTIFICATE`. `STATEMENT` y
  `TRANSACTION_RECEIPT` se reservan para documentos que genere el propio banco.
- Límites: 10 MB por documento y 14 MiB por petición (**413** antes de procesarla).
  Cada usuario tiene una cuota de 100 documentos y 100 MiB cifrados; la fila del usuario se
  bloquea durante la subida para que dos peticiones simultáneas no la superen. Además, cada
  usuario puede hacer 60 peticiones por minuto a `/api/documents` (ráfagas de 30); por encima
  recibe **429**.
- Quien no tiene acceso recibe **404**, igual que si el documento no existiera.
- El cliente fija la identidad del servidor: exige la huella de `SERVER_KEY_FINGERPRINT` o, si
  no está definida, la del primer inicio de sesión (TOFU), y no continúa si la clave cambia.
  Si regeneras `.keys/`, borra los datos del sitio en el navegador.
- La descarga se entrega como `application/octet-stream`, para que un HTML o SVG malicioso
  no se ejecute con el origen de la aplicación.
- `document_audit_events` registra subidas, descargas y eliminaciones (éxitos, rechazos y
  errores). Un *trigger* impide `UPDATE`, `DELETE` y `TRUNCATE`. Si una descarga no se puede
  auditar, no se entrega.
- Todas las respuestas de `/api` llevan `Cache-Control: no-store` y `X-Content-Type-Options: nosniff`.
- Caddy envía una CSP que solo permite scripts del propio origen y exige Trusted Types, además
  de otras cabeceras de seguridad. Un XSS no puede ejecutar código inyectado, que es lo que
  daría acceso a las claves privadas en memoria.

### Endpoints (requieren JWT)

| Método y ruta                | Qué hace                                               | Respuestas              |
|------------------------------|--------------------------------------------------------|-------------------------|
| `GET /api/documents`         | Lista los documentos accesibles y la cuota ocupada     | 200                     |
| `POST /api/documents`        | Sube un documento cifrado y firmado en el navegador    | 201, 400, 409, 413      |
| `GET /api/documents/:id`     | Entrega el documento cifrado tras verificar su firma   | 200, 400, 404, 500      |
| `DELETE /api/documents/:id`  | Elimina el documento y sus claves (solo el propietario) | 204, 400, 403, 404     |

### Preparado para compartir

`document_access` ya tiene `permission` (`OWNER`, `SHARE`, `READ`), `granted_by`,
`granted_at`, `revoked`/`revoked_at` y `key_algorithm`. Las consultas solo devuelven accesos
vigentes, así que un documento compartido aparecerá en el listado del destinatario y este no
podrá borrarlo (probado en `document_repository_security_test.go`). Para compartir faltará:

1. Un endpoint que entregue las claves públicas certificadas de otro usuario. El cliente
   verificará el certificado con la clave del banco antes de usarlas.
2. Que el cliente desenvuelva la clave AES y la vuelva a envolver con la clave pública del destinatario.
3. Un endpoint que inserte esa fila con permiso `SHARE` o `READ` y audite `SHARE` y `REVOKE`.
4. Revocar no borra la clave que el destinatario ya pudo descargar: para cortar el acceso a
   versiones nuevas hay que volver a cifrar el documento con otra clave.

### Probarlo

- **Interfaz:** inicia sesión → *Mis documentos*. Tras cada descarga se muestran las
  comprobaciones realizadas y la huella SHA-256.
- **Tests** (incluyen los de integración con PostgreSQL):
  `docker compose exec backend go test ./...`

### Demostrar los controles desde DBeaver

Sustituye `<id>` por el identificador que aparece bajo el nombre del documento.

```sql
-- 1. Manipular el contenido cifrado: el servidor se niega a entregarlo.
UPDATE documents SET encrypted_content = overlay(encrypted_content placing '\x00'::bytea from 100 for 1)
WHERE public_id = '<id>';

-- 2. Sustituir la clave envuelta por la de OTRO documento tuyo: el servidor no puede
--    detectarlo (no ve las claves), pero el navegador sí, gracias al compromiso de clave.
UPDATE document_access SET encrypted_aes_key = (
    SELECT a.encrypted_aes_key FROM document_access a
    JOIN documents d ON d.id = a.document_id WHERE d.public_id = '<otro id>')
WHERE document_id = (SELECT id FROM documents WHERE public_id = '<id>');

-- 3. Intentar borrar la auditoría: el trigger lo impide.
DELETE FROM document_audit_events;

-- Ver qué ha quedado auditado.
SELECT user_id, document_id, action, result, reason, created_at
FROM document_audit_events ORDER BY id DESC;
```

### Limitaciones conocidas

- Quien tenga la contraseña del propietario de las tablas (`POSTGRES_PASSWORD`) sí puede
  desactivar el *trigger* de auditoría: en producción no debería estar en el servidor de la aplicación.
- El servidor no puede buscar malware en documentos cifrados de extremo a extremo: es un
  compromiso inherente a este modelo.
- La contraseña no llega al servidor: el cliente deriva de ella una clave maestra
  (PBKDF2-SHA256, 600 000 iteraciones, con el correo como sal) y de esta, con HMAC-SHA256
  y una etiqueta distinta para cada uso, dos claves independientes. Solo envía la de
  autenticación; la que protege las claves privadas nunca sale del navegador. Aun así, un
  servidor malicioso podría intentar adivinar contraseñas débiles a partir de la clave de
  autenticación, y la política de contraseñas solo puede comprobarse en el cliente.
- La sesión viaja en una cookie `HttpOnly`, `Secure` y `SameSite=Strict` limitada a `/api`,
  así que JavaScript no puede leer el token. Cerrar sesión (o recargar la página) lo revoca,
  pero las revocaciones se guardan en memoria: si el backend se reinicia, el token de una
  sesión cerrada vuelve a valer hasta que caduca (una hora como máximo).

## Base de datos

### Esquema, migraciones y modelos GORM

- El esquema se gestiona con **migraciones SQL** en [database/migrations/](database/migrations/),
  que aplica [golang-migrate](https://github.com/golang-migrate/migrate) (servicio `migrate`
  de `compose.yaml`). Son la fuente de verdad: el backend **no** usa `AutoMigrate` ni
  modifica el esquema.
- Cada migración son dos ficheros con el mismo número:
  - `NNNNNN_descripcion.up.sql`: aplica el cambio.
  - `NNNNNN_descripcion.down.sql`: lo deshace.

  La primera, `000001_initial_schema`, crea las seis tablas: `users`, `accounts`,
  `account_users`, `transactions`, `documents` y `document_access`.
- golang-migrate guarda en la tabla `schema_migrations` la versión aplicada en cada base de
  datos. **No la modifiques a mano.**
- Las migraciones pendientes se aplican solas en cada `docker compose up`.
- [internal/models/](internal/models/) contiene un modelo GORM por tabla. Las columnas que
  admiten NULL son punteros (`*string`, `*int64`) y el dinero usa `decimal.Decimal`, nunca `float`.

Los comandos de esta sección están probados en PowerShell. En Git Bash, si un comando
contiene rutas como `/tmp/...`, antepón `MSYS_NO_PATHCONV=1` para que no las convierta.

### Inicializar el esquema en una instalación nueva

No hay que hacer nada especial: el primer `docker compose up --build` crea la base de datos
vacía y `migrate` aplica todas las migraciones. Para comprobarlo:

```sh
docker compose logs migrate               # debe aparecer: 1/u initial_schema
docker compose run --rm migrate version   # versión actual del esquema
curl.exe -k https://localhost:8443/api/health/db
```

Para empezar de cero (se pierden todos los datos): `docker compose down -v` y
`docker compose up --build`.

### Base de datos creada antes de las migraciones

Si tu volumen se creó con el sistema anterior (`database/init/001_schema.sql`), ya tiene las
tablas pero no la tabla `schema_migrations`, y `migrate` fallaría al intentar crearlas otra vez.

- **Sin datos que conservar:** `docker compose down -v` y `docker compose up --build`.
- **Con datos que conservar:** marca la migración 1 como aplicada (no ejecuta nada) y arranca:

  ```sh
  docker compose run --rm migrate force 1
  docker compose up -d --build
  ```

  Si ya hiciste `docker compose up` y `migrate` falló con `relation "users" already exists`,
  ejecuta esos mismos dos comandos: no se ha perdido nada.

### Cambiar el esquema (flujo de trabajo)

1. **Si tienes datos que te importen, haz una copia de seguridad.** Se guarda fuera del
   repositorio porque contiene datos:

   ```sh
   docker compose exec db pg_dump -U securitybank -d securitybank -Fc -f /tmp/securitybank.dump
   docker compose cp db:/tmp/securitybank.dump ../securitybank.dump
   ```

2. **Crea la migración.** Esto genera la pareja `000002_add_phone_to_users.up.sql` /
   `.down.sql` con el número siguiente (también puedes crear los dos ficheros a mano):

   ```sh
   docker compose run --rm migrate create -ext sql -dir . -seq add_phone_to_users
   ```

3. **Escribe el SQL** del cambio (`up`) y de cómo deshacerlo (`down`):

   ```sql
   -- 000002_add_phone_to_users.up.sql
   BEGIN;
   ALTER TABLE users ADD COLUMN phone VARCHAR(20);
   COMMIT;
   ```

   ```sql
   -- 000002_add_phone_to_users.down.sql
   BEGIN;
   ALTER TABLE users DROP COLUMN phone;
   COMMIT;
   ```

   - Usa siempre `BEGIN; ... COMMIT;`: si algo falla, no se aplica nada.
   - Prefiere cambios que no borran: `ADD COLUMN`, `CREATE INDEX`, `ADD CONSTRAINT`.
     Evita `DROP` y renombrar columnas con datos.
   - Para añadir una columna `NOT NULL` a una tabla con datos: añádela admitiendo NULL,
     rellénala con `UPDATE` y después `ALTER COLUMN ... SET NOT NULL`.

4. **Aplícala:**

   ```sh
   docker compose run --rm migrate up
   ```

   Antes de subirla, comprueba que el `down` también funciona:
   `docker compose run --rm migrate down 1` y otra vez `up`.

5. **Actualiza el modelo GORM** correspondiente. Air recompila el backend: revisa sus logs y
   `GET /api/health/db`.

6. **Haz commit de la migración y del modelo juntos.** Tus compañeros solo tienen que hacer
   `git pull` y `docker compose up -d`: la migración se aplica sola.

### Comandos de migraciones

| Comando                                        | Qué hace                                             |
|------------------------------------------------|------------------------------------------------------|
| `docker compose run --rm migrate version`      | Muestra la versión actual (y si está `dirty`)        |
| `docker compose run --rm migrate up`           | Aplica todas las migraciones pendientes              |
| `docker compose run --rm migrate down 1`       | Deshace la última migración (**puede borrar datos**) |
| `docker compose run --rm migrate force N`      | Marca la versión N como aplicada sin ejecutar nada   |
| `docker compose run --rm migrate create -ext sql -dir . -seq nombre` | Crea una migración nueva    |

### Si una migración falla

`migrate` muestra el error, la base de datos queda marcada como **dirty** en esa versión y
el backend no arranca. Puede aparecer también una línea con
`current transaction is aborted ... pg_advisory_unlock`: es una consecuencia del error y no
tiene importancia.

Gracias a `BEGIN; ... COMMIT;` no se ha aplicado nada. Para recuperarte, si falló la
versión N:

```sh
docker compose run --rm migrate force N-1   # por ejemplo, si falló la 2: force 1
# corrige el fichero .up.sql
docker compose run --rm migrate up
```

### Reglas

- **Todo cambio del esquema es una migración que se sube a Git.** No modifiques tablas desde
  el editor visual de DBeaver: ese cambio solo existiría en tu ordenador.
- **No edites una migración que ya está en Git**, porque tus compañeros ya la han aplicado.
  Si hay que corregir algo, crea una migración nueva.
- **No uses `AutoMigrate`** ni toques la tabla `schema_migrations` a mano.
- **Cada tabla nueva necesita su `GRANT` a `securitybank_app`** en la misma migración
  (solo `SELECT, INSERT` si es de auditoría). Sin él, el backend recibe `permission denied`.

### Restaurar una copia de seguridad

```sh
docker compose cp ../securitybank.dump db:/tmp/securitybank.dump
docker compose exec db pg_restore -U securitybank -d securitybank --clean --if-exists /tmp/securitybank.dump
```

## Conectar DBeaver

1. **Base de datos → Nueva conexión** (o el icono del enchufe) → **PostgreSQL** → Siguiente.
2. En la pestaña **Principal**:

   | Campo         | Valor                                       |
   |---------------|---------------------------------------------|
   | Host          | `localhost`                                 |
   | Port          | `5432` (o el valor de `POSTGRES_HOST_PORT`) |
   | Database      | `securitybank`                              |
   | Username      | `securitybank`                              |
   | Password      | el valor de `POSTGRES_PASSWORD` en `.env`   |

3. **Probar conexión**. La primera vez, DBeaver ofrece descargar el driver de PostgreSQL: acepta.
4. **Finalizar**. Los contenedores deben estar en marcha (`docker compose up -d`).

Si la conexión falla con un error de contraseña, comprueba que no tienes otro PostgreSQL
(por ejemplo, el servicio de Windows) escuchando en el mismo puerto.

### Ver las tablas y sus relaciones

- **Tablas:** en el navegador de bases de datos, despliega
  `securitybank → Bases de datos → securitybank → Esquemas → public → Tablas`.
  Pulsa F5 sobre la conexión si acabas de crear el esquema. Además de las tablas del banco verás
  `schema_migrations`: es la tabla de control de golang-migrate, no la modifiques.
- **Detalle de una tabla:** haz doble clic sobre ella. En la pestaña **Propiedades** verás
  *Columnas* (con los comentarios del esquema), *Restricciones* (primary keys, UNIQUE y CHECK),
  *Claves foráneas*, *Referencias* (qué tablas apuntan a esta) e *Índices*. La pestaña
  **Datos** muestra el contenido.
- **Diagrama de relaciones:** clic derecho sobre `public` → **Ver diagrama** (*View Diagram*).
  Muestra las tablas y las líneas de sus claves foráneas. Cada tabla tiene también su
  propia pestaña **Diagrama ER**.
- **Relaciones con SQL** (Editor SQL, Ctrl+Intro para ejecutar):

  ```sql
  SELECT conrelid::regclass AS tabla, conname AS restriccion, pg_get_constraintdef(oid) AS definicion
  FROM pg_constraint
  WHERE contype = 'f' AND connamespace = 'public'::regnamespace
  ORDER BY 1;
  ```
