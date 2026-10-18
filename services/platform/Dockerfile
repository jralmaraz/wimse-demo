FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /platform ./services/platform/cmd/

FROM gcr.io/distroless/static-debian12
COPY --from=builder /platform /platform
# SPIRE sim on 8081, AS on 8082
EXPOSE 8081 8082
ENTRYPOINT ["/platform"]
