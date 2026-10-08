# securityBank_server

Backend de SecurityBank (Go + Gin + GORM) y entorno de desarrollo local con Docker Compose
(frontend Vue 3, backend Go y PostgreSQL 17).

## Requisitos previos

- **Docker Desktop** instalado y en ejecución.
- **Git**, con los dos repositorios clonados uno al lado del otro (ver estructura).
- **DBeaver** (opcional) para consultar la base de datos.
- Puertos libres en tu ordenador: **5173** (frontend), **8080** (backend) y **5432** (PostgreSQL).
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
    │   ├── handlers/                 # Manejadores HTTP (endpoints de salud)
    │   └── models/                   # Modelos GORM de las seis tablas
    ├── database/migrations/          # Migraciones SQL: fuente de verdad de la base de datos
    ├── compose.yaml                  # Servicios frontend, backend, db y migrate
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
| `DATABASE_URL`       | Conexión del backend. Se construye con las variables anteriores          |
| `BACKEND_PORT`       | Puerto del backend (`8080`)                                              |
| `CORS_ORIGIN`        | Origen del frontend permitido por CORS (`http://localhost:5173`)         |

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

| Servicio   | URL                                 |
|------------|-------------------------------------|
| Frontend   | http://localhost:5173               |
| Backend    | http://localhost:8080/api/health    |
| PostgreSQL | localhost:5432                      |

Al guardar cambios, Vite recarga el frontend y Air recompila el backend automáticamente.

Orden de arranque: PostgreSQL → `migrate` (aplica las migraciones pendientes y termina) →
backend. Si una migración falla, el backend no arranca. En `docker compose ps -a`, el
servicio `migrate` aparece como `Exited (0)`: es lo normal.

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
| `GET /api/health/db`  | Que PostgreSQL responde y existen las seis tablas | `{"database":"ok","schema":"ok","status":"ok"}`     |

Si PostgreSQL no responde, `/api/health/db` devuelve **503** con `"database":"unavailable"`;
si faltan tablas, **503** con `"schema":"incomplete"` (el detalle aparece en los logs del backend).

Desde el navegador o desde la terminal:

```sh
curl.exe http://localhost:8080/api/health       # PowerShell (curl a secas es otro comando)
curl.exe http://localhost:8080/api/health/db
curl http://localhost:8080/api/health/db        # Git Bash
```

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
curl.exe http://localhost:8080/api/health/db
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
  Pulsa F5 sobre la conexión si acabas de crear el esquema. Además de las seis tablas verás
  `schema_migrations`: es la tabla de control de golang-migrate, no la modifiques.
- **Detalle de una tabla:** haz doble clic sobre ella. En la pestaña **Propiedades** verás
  *Columnas* (con los comentarios del esquema), *Restricciones* (primary keys, UNIQUE y CHECK),
  *Claves foráneas*, *Referencias* (qué tablas apuntan a esta) e *Índices*. La pestaña
  **Datos** muestra el contenido.
- **Diagrama de relaciones:** clic derecho sobre `public` → **Ver diagrama** (*View Diagram*).
  Muestra las seis tablas y las líneas de sus claves foráneas. Cada tabla tiene también su
  propia pestaña **Diagrama ER**.
- **Relaciones con SQL** (Editor SQL, Ctrl+Intro para ejecutar):

  ```sql
  SELECT conrelid::regclass AS tabla, conname AS restriccion, pg_get_constraintdef(oid) AS definicion
  FROM pg_constraint
  WHERE contype = 'f' AND connamespace = 'public'::regnamespace
  ORDER BY 1;
  ```
