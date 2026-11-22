# Fatima Desk Console image: one static Go binary, nothing else.
# The binary is built beforehand (see console/README.md):
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o build/fatimadesk-console .
FROM scratch
COPY build/fatimadesk-console /fatimadesk-console
# SQLite may need a temp directory; WORKDIR creates /tmp in a scratch image.
WORKDIR /tmp
EXPOSE 8080
ENTRYPOINT ["/fatimadesk-console"]
