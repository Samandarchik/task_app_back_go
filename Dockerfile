# ============================
#       BUILD STAGE
# ============================
FROM golang:1.24 AS builder

WORKDIR /app

# Go mod fayllarini ko'chirish
COPY go.mod go.sum ./
RUN go mod download

# Barcha kodni ko‘chirish
COPY . .

# Go binary build qilish
RUN CGO_ENABLED=1 go build -o server .

# ============================
#       FINAL STAGE
# ============================
FROM debian:bookworm

WORKDIR /app

# SQLite ishlashi uchun kutubxonalar
RUN apt-get update && apt-get install -y \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Proyekt papkalarini yaratib qo'yamiz
RUN mkdir -p /app/db /app/videos

# Builderdan binarni olish
COPY --from=builder /app/server /app/server

# PORT
EXPOSE 8000

# Run server
CMD ["/app/server"]
