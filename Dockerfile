FROM golang:1.20.5 as base
ARG VERSION
WORKDIR /service
ENV GOBIN /service/bin
COPY ./api ./api
COPY ./cmd ./cmd\
COPY ./internal ./internal
COPY ./keys ./keys

COPY ./go.mod ./
COPY ./go.sum ./

RUN go install -buildvcs=false -ldflags "-X main.build=${VERSION}" ./cmd/...


FROM alpine:latest
RUN apk add --no-cache libstdc++ gcompat libgomp
RUN apk add --update busybox>1.3.1-r0
RUN apk add --update openssl>3.1.4-r1

RUN apk add doas; \
    adduser -S verifier -D -G wheel; \
    echo 'permit nopass :wheel as root' >> /etc/doas.d/doas.conf;
RUN chmod g+rx,o+rx /

COPY --from=base ./service/api ./api
COPY --from=base ./service/bin/* ./
COPY --from=base ./service/keys ./keys