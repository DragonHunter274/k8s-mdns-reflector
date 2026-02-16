FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /mdns-reflector .

FROM gcr.io/distroless/static-debian12
COPY --from=build /mdns-reflector /mdns-reflector
ENTRYPOINT ["/mdns-reflector"]
