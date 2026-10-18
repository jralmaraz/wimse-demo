FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /apis ./services/apis/cmd/

FROM gcr.io/distroless/static-debian12
COPY --from=builder /apis /apis
# fraud-api on 8084, compliance-reporter on 8085
EXPOSE 8084 8085
ENTRYPOINT ["/apis"]
