# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY internal/ internal/
COPY cmd/ cmd/
RUN CGO_ENABLED=0 go build -o /out/keyrot ./cmd/keyrot

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/keyrot /app/keyrot
EXPOSE 8080
ENTRYPOINT ["/app/keyrot"]
CMD ["serve", "--addr", ":8080", "--store", "/app/data/keystore.json"]
