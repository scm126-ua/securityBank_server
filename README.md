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
    │   └── models/                   # Modelos GORM de las seis tablas (+ tests)
    ├── database/init/001_schema.sql  # Esquema SQL: fuente de verdad de la base de datos
    ├── compose.yaml                  # Servicios frontend, backend y db
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
El backend no arranca hasta que PostgreSQL está preparado (healthcheck).

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

### Esquema y modelos GORM

- [database/init/001_schema.sql](database/init/001_schema.sql) define las seis tablas: `users`,
  `accounts`, `account_users`, `transactions`, `documents` y `document_access`. Es la fuente
  de verdad: el backend **no** usa `AutoMigrate` ni modifica el esquema.
- [internal/models/](internal/models/) contiene un modelo GORM por tabla. Las columnas que
  admiten NULL son punteros (`*string`, `*int64`) y el dinero usa `decimal.Decimal`, nunca `float`.
- Los tests comprueban que los modelos coinciden con el esquema real (tablas, columnas, tipos,
  NULL, claves primarias y foráneas). Solo leen la base de datos:

  ```sh
  docker compose exec backend go test -count=1 ./...
  ```

### Inicializar el esquema en una instalación nueva

Con el volumen vacío (primer `docker compose up`), PostgreSQL ejecuta automáticamente los
scripts de `database/init/` (montado en `/docker-entrypoint-initdb.d/`) en orden alfabético.
Para comprobarlo:

```sh
docker compose logs db          # debe aparecer: running /docker-entrypoint-initdb.d/001_schema.sql
curl.exe http://localhost:8080/api/health/db
```

Si el volumen ya existe, los scripts **no se vuelven a ejecutar**. Para empezar de cero
(se pierden todos los datos): `docker compose down -v` y `docker compose up --build`.

### Aplicar cambios SQL sin eliminar datos

1. **Haz una copia de seguridad** (se guarda fuera del repositorio porque contiene datos):

   ```sh
   docker compose exec db pg_dump -U securitybank -d securitybank -Fc -f /tmp/securitybank.dump
   docker compose cp db:/tmp/securitybank.dump ../securitybank.dump
   ```

2. **Crea un script nuevo** en `database/init/` con el siguiente número, por ejemplo
   `002_add_phone_to_users.sql`. No modifiques `001_schema.sql`: tus compañeros ya lo han
   aplicado. Así, las instalaciones nuevas ejecutan 001 y 002 automáticamente.

   ```sql
   BEGIN;
   ALTER TABLE users ADD COLUMN phone VARCHAR(20);
   COMMIT;
   ```

   - Usa siempre `BEGIN; ... COMMIT;`: si algo falla, no se aplica nada.
   - Prefiere cambios que no borran: `ADD COLUMN`, `CREATE INDEX`, `ADD CONSTRAINT`.
     Evita `DROP` y renombrar columnas con datos.
   - Para añadir una columna `NOT NULL` a una tabla con datos: añádela admitiendo NULL,
     rellénala con `UPDATE` y después `ALTER COLUMN ... SET NOT NULL`.

3. **Aplica el script** a tu base de datos existente (PowerShell):

   ```sh
   docker compose exec db psql -v ON_ERROR_STOP=1 -U securitybank -d securitybank -f /docker-entrypoint-initdb.d/002_add_phone_to_users.sql
   ```

   En Git Bash, antepón `MSYS_NO_PATHCONV=1` para que no convierta la ruta. También puedes
   abrir el script en DBeaver y ejecutarlo (Alt+X).

4. **Actualiza el modelo GORM** correspondiente y ejecuta los tests
   (`docker compose exec backend go test -count=1 ./...`).

5. **Haz commit del script y del modelo juntos.** Cada compañero aplica el nuevo script con
   el paso 3.

Si algo sale mal, restaura la copia de seguridad:

```sh
docker compose cp ../securitybank.dump db:/tmp/securitybank.dump
docker compose exec db pg_restore -U securitybank -d securitybank --clean --if-exists /tmp/securitybank.dump
```

Cuando los cambios de esquema sean frecuentes, conviene pasar a una herramienta de
migraciones (por ejemplo golang-migrate o goose), que registra qué scripts se han aplicado.

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
  Pulsa F5 sobre la conexión si acabas de crear el esquema.
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
