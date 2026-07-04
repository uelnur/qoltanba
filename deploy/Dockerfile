# qoltanba runtime image. BYOL: the Kalkan native library is NOT baked in —
# mount it at runtime (see compose.yaml). The binary must be glibc (not musl):
# Kalkan's glibc build is dlopen'd into the same process, and two libc in one
# process crash it — so both stages use Debian, not Alpine.

# ── build ──
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# cgo is required (the driver compiles a C shim); dlopen of the library happens
# at runtime, so the native lib is not needed to build.
ENV CGO_ENABLED=1
RUN go build -trimpath -ldflags "-X main.version=$(git describe --tags --always 2>/dev/null || echo docker)" \
    -o /out/qoltanba ./cmd/qoltanba

# ── runtime ──
FROM debian:bookworm-slim
# Kalkan typically needs an OpenSSL-1.1 fork + iconv at load time; those are part
# of the BYOL bundle the consumer mounts (see native/ and test/functional/).
RUN useradd --system --uid 10001 kalkan
COPY --from=build /out/qoltanba /usr/local/bin/qoltanba
USER kalkan
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/qoltanba"]
