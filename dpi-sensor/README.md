# mikrodash-dpi

The sensor behind MikroDash's **IPS** page. It runs as a container on the
MikroTik, classifies the traffic the router copies to it with
[nDPI](https://github.com/ntop/nDPI), and hands each classified flow to
MikroDash, which decides what to block.

```
router: mangle action=sniff-tzsp (first bytes of each connection)
   │  UDP 37008, TZSP
   ▼
mikrodash-dpi  ── nDPI ──►  one JSON line per flow
   ▲  TCP 37009, "HELLO <token>"
   │
MikroDash: rules → address lists on the router
```

It never writes to the router and holds no state worth keeping: restarting it
loses only the flows in progress.

## Running it

The IPS page's **Setup** tab generates the RouterOS commands for your router,
with the token filled in. By hand, it takes:

| Flag | Environment | Default | |
|---|---|---|---|
| `--token` | `DPI_TOKEN` | (required) | at least 16 characters; MikroDash sends it to read |
| `--tzsp-port` | `DPI_TZSP_PORT` | 37008 | where the router sends TZSP |
| `--listen-port` | `DPI_LISTEN_PORT` | 37009 | where MikroDash reads |
| `--max-flows` | `DPI_MAX_FLOWS` | 32768 | flows tracked at once; the oldest is reported and dropped |
| `--idle` | `DPI_IDLE_SECONDS` | 120 | a flow idle this long is reported (if it was not) and forgotten |

## What it sends

One JSON object a line: `hello` once, `stats` every five seconds, and a `flow`
for every flow once nDPI has classified it or given up:

```json
{"type":"flow","ts":1793140197936,"l4":"tcp","client":"192.168.88.20","clientPort":52888,
 "server":"203.0.113.7","serverPort":443,"name":"TLS.NetFlix","app":"NetFlix","master":"TLS",
 "category":"Video","breed":"Fun","host":"www.netflix.com","risks":[],"guessed":false,
 "packets":6,"bytes":2210}
```

## Testing without a router

`tools/tzsp-replay.py` sends a pcap to the sensor as the router would:

```sh
./mikrodash-dpi --token 0123456789abcdef0123 &
python3 tools/tzsp-replay.py capture.pcap 127.0.0.1 37008
```
