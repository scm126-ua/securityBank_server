# Imagen de desarrollo del backend: Go + Air (recarga automática).
#
# go.mod declara Go 1.25.6 como versión mínima del lenguaje. La imagen usa
# Go 1.26, una versión con soporte que compila ese código sin cambios.
FROM golang:1.26.9-alpine3.24

# Air vuelve a compilar y reiniciar la API cada vez que cambia un fichero .go.
RUN go install github.com/air-verse/air@v1.67.4

WORKDIR /app

# Primero solo las dependencias, para aprovechar la caché de capas de Docker.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compilación inicial: deja la caché de Go preparada para que Air arranque rápido.
RUN go build -o /tmp/air/api ./cmd/api

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]
