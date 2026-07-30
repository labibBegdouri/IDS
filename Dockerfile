# multistage building because go image is heavy 800 MO
FROM golang:1.23-alpine AS builder

WORKDIR /usr/src/app

# gcc/musl-dev pour CGO, libpcap-dev pour les headers de compilation
RUN apk add --no-cache gcc musl-dev libpcap-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=1 --> dynamic binary
RUN CGO_ENABLED=1 GOOS=linux go build -v -o /ids .

# alpine is lightweight linux distro to run our program
FROM alpine:latest

# libpcap runtime (nécessaire à l'exécution, pas juste à la compilation)
RUN apk add --no-cache libpcap

WORKDIR /app
COPY --from=builder /ids /usr/local/bin/ids
WORKDIR /usr/src/app
COPY whitelist.txt .

# ENTRYPOINT fixe + CMD comme valeur par défaut du paramètre (interface)
ENTRYPOINT ["ids"]
CMD ["eth0"]