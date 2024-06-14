FROM golang:1.22-alpine AS builder
WORKDIR /build
RUN apk add --update make
ADD . /build
RUN make attache

FROM golang:1.22-alpine AS runner
LABEL org.opencontainers.image.source="https://github.com/DataDog/attache/"
COPY --from=builder /build/attache /attache
ENTRYPOINT ["/attache"]