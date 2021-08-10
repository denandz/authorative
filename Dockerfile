FROM golang:latest as builder
RUN mkdir /go/src/authorative 
ADD . /go/src/authorative/
WORKDIR /go/src/authorative/
RUN go get ./...
RUN CGO_ENABLED=0 GOOS=linux go build -v -a -installsuffix cgo -ldflags '-extldflags "-static"' -o authorative .
FROM scratch
COPY --from=builder /go/src/authorative/authorative /app/
COPY --from=builder /go/src/authorative/login.html /app/
WORKDIR /app
CMD ["./authorative"]