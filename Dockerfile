FROM node:20.11-alpine3.18 as build

RUN corepack enable

# Move files into the image and install
WORKDIR /app
COPY ./service ./
RUN corepack prepare --activate
RUN pnpm install --production --frozen-lockfile > /dev/null

# Build Go pdsadmin binary
FROM docker.io/library/golang:1.21-alpine AS gobuild
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=linux go build -o pdsadmin ./cmd/pdsadmin

# Uses assets from build stage to reduce build size
FROM node:20.11-alpine3.18

RUN apk add --update dumb-init

# Avoid zombie processes, handle signal forwarding
ENTRYPOINT ["dumb-init", "--"]

WORKDIR /app
COPY --from=build /app /app
COPY --from=gobuild /src/pdsadmin /usr/local/bin/pdsadmin
RUN chmod +x /usr/local/bin/pdsadmin

EXPOSE 3000
ENV PDS_PORT=3000
ENV NODE_ENV=production
# potential perf issues w/ io_uring on this version of node
ENV UV_USE_IO_URING=0

CMD ["node", "--enable-source-maps", "index.js"]

LABEL org.opencontainers.image.source=https://github.com/bluesky-social/pds
LABEL org.opencontainers.image.description="AT Protocol PDS"
LABEL org.opencontainers.image.licenses=MIT
