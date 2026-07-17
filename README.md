# pandemonium-proxy

`pandemonium-proxy` is a private companion repository containing a small authenticated forward proxy for Pandemonium's
daemon-owned outbound HTTP client. It is intended to run on a private or VPN
interface of a host with a stable public IPv4.

It supports regular HTTP proxy requests and HTTPS `CONNECT`. Every relayed
request requires a short-lived Ed25519 signature from Pandemonium. The proxy
stores only the daemon public key; the daemon private key never leaves the
Pandemonium host. The unauthenticated
origin-form `GET /healthz` endpoint is local health state only.

## Build and test

```sh
go test ./...
go build -trimpath -ldflags "-s -w" -o pandemonium-proxy .
```

## Run

```sh
export PANDEMONIUM_PROXY_LISTEN=10.0.0.4:3128
export PANDEMONIUM_PROXY_PUBLIC_KEY_PATH=/etc/pandemonium-proxy/daemon-public.pem
./pandemonium-proxy
```

The default listener is `127.0.0.1:3128`. Set the listener to a private/VPN
address where possible and restrict ingress to the Pandemonium daemon host.

Generate the daemon key pair once on the Pandemonium host:

```sh
openssl genpkey -algorithm Ed25519 -out daemon-private.pem
openssl pkey -in daemon-private.pem -pubout -out daemon-public.pem
```

Keep `daemon-private.pem` on the daemon host with mode `0600`. Copy only
`daemon-public.pem` to the proxy host.

Install the built binary at `/usr/local/bin/pandemonium-proxy`, copy the supplied
systemd unit to `/etc/systemd/system/`, and store mode-`0600` configuration in
`/etc/pandemonium-proxy.env`:

```ini
PANDEMONIUM_PROXY_LISTEN=10.0.0.4:3128
PANDEMONIUM_PROXY_PUBLIC_KEY_PATH=/etc/pandemonium-proxy/daemon-public.pem
```

Pandemonium consumes it through a credential-free URL while Networking owns the
private key:

```ini
SERVICE_NETWORKING_PROXY_PRIVATE_KEY_PATH=/etc/pandemonium/daemon-proxy-private.pem
NAMECHEAP_PROXY_URL=http://10.0.0.4:3128
NAMECHEAP_CLIENT_IP=203.0.113.10
```

Whitelist the proxy host's actual public IPv4 in Namecheap. Logs intentionally
contain only method, destination host/port, status, byte count, and duration.
