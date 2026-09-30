# The Identity Hub as one small image: the dashboard is built, embedded in
# the Go binary, and the binary runs on a minimal base as a non-root user.
# Settings come from the environment (see .env.example); no .env is baked in.

FROM node:22-alpine AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY ui/ui.go ./ui/ui.go
COPY --from=ui /src/ui/dist ./ui/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hub ./cmd/hub

FROM alpine:3.21
# Certificates to reach Asgardeo over TLS; wget for the health check.
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 10001 hub
COPY --from=build /out/hub /usr/local/bin/hub
USER hub
WORKDIR /home/hub
ENV HUB_ADDR=:8090
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
    CMD wget -qO- http://127.0.0.1${HUB_ADDR}/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/hub"]
