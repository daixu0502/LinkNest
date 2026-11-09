FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm AS build
ARG TARGETARCH
ARG GOPROXY=https://proxy.golang.org,direct
ENV CGO_ENABLED=0 GOMAXPROCS=2 GOMEMLIMIT=256MiB
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test -trimpath ./... && GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/linknest ./cmd/linknest
RUN mkdir -p /out/licenses && cp /usr/local/go/LICENSE /out/licenses/GO-LICENSE \
    && cp "$(go list -m -f '{{.Dir}}' golang.org/x/crypto)/LICENSE" /out/licenses/XCRYPTO-LICENSE \
    && cp "$(go list -m -f '{{.Dir}}' golang.org/x/sys)/LICENSE" /out/licenses/XSYS-LICENSE \
    && cp /go/pkg/mod/github.com/gorilla/websocket@v1.5.3/LICENSE /out/licenses/WEBSOCKET-LICENSE \
    && cp web/vendor/LICENSE /out/licenses/XTERM-LICENSE \
    && cp web/vendor/NotoSansSC-OFL.txt /out/licenses/UI-FONT-LICENSE \
    && cp /go/pkg/mod/github.com/skip2/go-qrcode@v0.0.0-20200617195104-da1b6568686e/LICENSE /out/licenses/QRCODE-LICENSE \
    && cp THIRD_PARTY.md /out/licenses/THIRD_PARTY.md

FROM debian:bookworm-slim AS runtime-files
ARG DEBIAN_MIRROR=http://deb.debian.org
RUN sed -i "s|http://deb.debian.org|${DEBIAN_MIRROR}|g" /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 update \
    && apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 install -y --no-install-recommends ca-certificates iptables tzdata python3 \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/minimal-runtime.py /extract-runtime.py
RUN python3 /extract-runtime.py --rootfs / --destination /out/runtime

FROM scratch
COPY --from=runtime-files /out/runtime/ /
COPY --from=build /out/linknest /usr/local/bin/linknest
COPY --from=build /out/licenses /usr/share/doc/linknest
ENV LINKNEST_DATA_DIR=/data LINKNEST_ADMIN_ADDR=127.0.0.1:17880 LINKNEST_FIREWALL=disabled \
    GOMEMLIMIT=128MiB GOMAXPROCS=2 TZ=Asia/Shanghai
VOLUME ["/data"]
EXPOSE 17880/tcp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["linknest", "healthcheck"]
ARG VERSION=1.2.5
ARG SOURCE_REVISION=unknown
ARG BUILD_DATE
LABEL org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$SOURCE_REVISION \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.source="https://github.com/daixu0502/linknest"
ENTRYPOINT ["/usr/local/bin/linknest"]
