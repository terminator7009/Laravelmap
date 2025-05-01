FROM golang:1.20-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Copy go.mod and go.sum files
COPY go.mod ./
COPY go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o laravelmap ./cmd/main.go

# Create final lightweight image
FROM alpine:3.18

WORKDIR /app

# Install necessary runtime packages
RUN apk add --no-cache ca-certificates tzdata

# Copy the binary from the builder stage
COPY --from=builder /app/laravelmap /app/laravelmap

# Set the entrypoint
ENTRYPOINT ["/app/laravelmap"]

# Default command if none is provided
CMD ["--help"]
