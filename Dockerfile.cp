# krot-cp: control plane binary.
FROM golang:1.26.4-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/krot-cp/ cmd/krot-cp/
COPY internal/store/ internal/store/
COPY internal/model/ internal/model/
COPY internal/render/ internal/render/
COPY internal/authentik/ internal/authentik/
COPY internal/directory/ internal/directory/
COPY internal/zitadel/ internal/zitadel/
COPY internal/oidc/ internal/oidc/
COPY internal/sub/ internal/sub/
COPY internal/web/ internal/web/
COPY internal/cpapi/ internal/cpapi/

RUN go tool templ generate ./internal/web

RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/krot-cp ./cmd/krot-cp

FROM alpine:3.20

LABEL org.opencontainers.image.title="krot-cp" \
      org.opencontainers.image.description="Krot control plane: portal, subscriptions, agent API, identity sync" \
      org.opencontainers.image.source="https://github.com/Arsolitt/krot" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

COPY --from=build /out/krot-cp /app

RUN addgroup -g 2222 -S krot && adduser -u 1111 -S -G krot krot \
    && mkdir -p /tmp && chown krot:krot /tmp

USER 1111:2222

ENTRYPOINT ["/app"]
