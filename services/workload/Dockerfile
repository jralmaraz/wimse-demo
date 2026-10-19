FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /workload ./services/workload/cmd/

FROM gcr.io/distroless/static-debian12
COPY --from=builder /workload /workload
EXPOSE 8083
ENTRYPOINT ["/workload"]
