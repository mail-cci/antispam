# Simple multi-stage build for development
FROM golang:1.23 AS builder
WORKDIR /app
COPY . .
RUN go build -o antispam ./cmd/antispam

FROM debian:stable-slim
WORKDIR /app
COPY --from=builder /app/antispam /usr/local/bin/antispam
COPY config/config.yaml /etc/antispam/config.yaml
EXPOSE 8080
CMD ["/usr/local/bin/antispam"]
