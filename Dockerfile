# Build and runtime image for cert
# Usage:
#   docker build -t cert:latest -f Dockerfile .
#   docker run --rm -v "$PWD":/work cert:latest

FROM golang:1.25.1-alpine AS build
WORKDIR /src

# Copy go module files and download dependencies first for better caching
RUN go install github.com/kisom/cert@v1.3.0 && \
    mv /go/bin/cert /usr/local/bin/cert

# Runtime stage (kept as golang:alpine per requirement)
FROM golang:1.24.3-alpine

WORKDIR /work
VOLUME ["/work"]

COPY --from=build /usr/local/bin/cert /usr/local/bin/cert

ENTRYPOINT ["/usr/local/bin/cert"]
