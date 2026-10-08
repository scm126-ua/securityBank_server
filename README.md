# securityBank_server

Backend de SecurityBank (Go + Gin + GORM) y entorno de desarrollo local con Docker Compose.

## Estructura

Los dos repositorios deben estar uno al lado del otro:

```
SecurityBank/
├── securityBank_client/
│   └── securityBank_client/   # Proyecto Vue 3 + Vite (frontend)
└── securityBank_server/       # Este repositorio (backend + compose.yaml)
    ├── cmd/api/main.go        # Punto de entrada: Gin, CORS y GET /api/health
    ├── internal/config/       # Lectura de variables de entorno
    ├── internal/database/     # Conexión con PostgreSQL mediante GORM
    ├── database/init/         # Scripts SQL del esquema (001_schema.sql)
    ├── .air.toml              # Recarga automática del backend
    ├── compose.yaml           # Servicios frontend, backend y db
    ├── Dockerfile
    └── .env.example
```

## Arranque

Requisito: Docker Desktop en ejecución.

```sh
cp .env.example .env          # solo la primera vez (en PowerShell: Copy-Item .env.example .env)
docker compose up --build
```

| Servicio   | URL                                    |
|------------|----------------------------------------|
| Frontend   | http://localhost:5173                  |
| Backend    | http://localhost:8080/api/health       |
| PostgreSQL | localhost:5432 (ver `POSTGRES_HOST_PORT`) |

Al guardar cambios, Vite recarga el frontend y Air recompila el backend automáticamente.

## Parada

```sh
docker compose down           # detiene los servicios; los datos de PostgreSQL se conservan
docker compose down -v        # detiene los servicios y BORRA los datos de PostgreSQL
```

## Comandos útiles

```sh
docker compose up -d --build              # arrancar en segundo plano
docker compose logs -f backend            # ver los logs de un servicio
docker compose ps                         # estado de los contenedores
docker compose up --build -V frontend     # tras cambiar package.json: reinstala node_modules
```

## Esquema de la base de datos

El esquema está en [database/init/001_schema.sql](database/init/001_schema.sql) y es la
fuente de verdad: el backend no usa `AutoMigrate` de GORM. Crea seis tablas:
`users`, `accounts`, `account_users`, `transactions`, `documents` y `document_access`.

**Volumen vacío (primer arranque):** PostgreSQL ejecuta automáticamente los scripts de
`database/init/` (montado en `/docker-entrypoint-initdb.d/`). Si el volumen ya tiene
datos, esos scripts **no se vuelven a ejecutar**.

**Volumen con datos que quieres conservar:** aplica el script a mano (PowerShell):

```sh
docker compose up -d db
docker compose exec db psql -v ON_ERROR_STOP=1 -U securitybank -d securitybank -f /docker-entrypoint-initdb.d/001_schema.sql
```

En Git Bash, antepón `MSYS_NO_PATHCONV=1` al segundo comando para que no convierta la ruta.
También puedes abrir el fichero en DBeaver y ejecutarlo como script (Alt+X).

El script se ejecuta en una única transacción y no borra nada: si alguna tabla ya existe,
falla con `relation ... already exists` y no aplica ningún cambio. Los cambios futuros
del esquema irán en scripts nuevos (`002_...sql`) con `ALTER TABLE`, que se aplican igual.

**Volumen sin datos que conservar:** `docker compose down -v` y `docker compose up` para
recrearlo desde cero (se borran todos los datos).

## Conexión con DBeaver

| Campo         | Valor                                        |
|---------------|----------------------------------------------|
| Host          | localhost                                    |
| Puerto        | 5432 (o el valor de `POSTGRES_HOST_PORT`)    |
| Base de datos | valor de `POSTGRES_DB` (`securitybank`)      |
| Usuario       | valor de `POSTGRES_USER` (`securitybank`)    |
| Contraseña    | valor de `POSTGRES_PASSWORD` en tu `.env`    |

Si tienes PostgreSQL instalado en Windows, ese servicio ya ocupa el puerto 5432:
detenlo o pon `POSTGRES_HOST_PORT=5433` en `.env` y conecta DBeaver al 5433.
