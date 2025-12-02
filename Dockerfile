FROM golang:alpine as builder

RUN apk add --no-cache make git

WORKDIR /go/src/github.com/micromdm/micromdm/

COPY . .

ENV CGO_ENABLED=0 \
	GOARCH=amd64 \
	GOOS=linux

RUN make deps
RUN make