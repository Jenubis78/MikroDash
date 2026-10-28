# The Traffic Analysis page

What the routers' traffic is, by application, category, host and country:
Traffic Flow (IPFIX) gives the volumes, the IPS sensor's nDPI gives the names
(`docs/ips.md`). Live is the last minute; History goes back a year.

## How it works

1. The router exports every connection once a minute (`/ip/traffic-flow`,
   `active-flow-timeout=1m`) to MikroDash on UDP 2055.
2. MikroDash decodes the IPFIX (`internal/ipfix`) and names each record with the
   connection the IPS sensor classified, under every pairing of its plain and
   NAT-translated addresses (`internal/traffic/join.go`). A connection the sensor
   did not name keeps its bytes as `Unknown`, with the remote organisation and
   port, or `Router` for the router's own traffic.
3. A minute's rows (host, application, category, country, received, sent,
   connections) go to the backend chosen in Setup.

A datagram is read only when it comes from an address of a router set up here;
anything else is counted as a stray and dropped. Nothing listens on the port
until the first router's Traffic Flow is applied.

## Or the IPS sensor, when it inspects every packet

A router whose IPS sensor is set to *Every packet* (IPS › Setup › Inspection)
needs no Traffic Flow. The sensor (version 2 and later) counts each
connection's bytes and sends them every five seconds, beside the application
it named; Live is then the last 30 seconds, refreshed every five, and the
minutes are stored as usual. IPFIX from such a router is counted as ignored,
never added a second time, and its Traffic Flow plan is the removal: Preview
shows MikroDash's target coming off (and Traffic Flow with it, when no other
collector uses it). The UDP port closes when no router needs it.

## Backends

| | SQLite (default) | ClickHouse |
|---|---|---|
| Where | `/data/traffic.db`, beside the app's database | your server, over its HTTP interface (8123) |
| Totals | 48 h by minute, 90 days by hour, 1 year by day | 1 year by minute |
| Flows | the last 15 minutes, in memory | every flow, kept *Keep flows, days* (90 by default) |
| Setup | none | a ClickHouse server; MikroDash creates the database and its two tables |

The choice is in **Setup › Storage**. A ClickHouse backend is opened before it is
saved: a URL or password it refuses is refused with its reason, and the backend
in use stays. The password is stored encrypted. While a backend is down, up to
two hours of rows wait in memory and Live keeps working.

A ClickHouse server with Docker, beside MikroDash:

```bash
docker run -d --name clickhouse -p 8123:8123 -v clickhouse:/var/lib/clickhouse \
  -e CLICKHOUSE_USER=mikrodash -e CLICKHOUSE_PASSWORD=change-me clickhouse/clickhouse-server
```

## Setting it up

1. Publish the IPFIX port on the container: `2055:2055/udp` (both compose files
   do).
2. **Setup › Storage**: choose the backend; leave *Collector address* empty
   unless the router reaches MikroDash through NAT.
3. **This router's Traffic Flow**: *Interfaces counted* is `all` by default;
   the WAN interface alone counts internet traffic only.
4. **Preview, then Apply**: Traffic Flow on, one export a minute, a target to
   MikroDash, the IPFIX fields the join reads. Remove takes MikroDash's target
   away and turns Traffic Flow off only if no other target is left.
5. With the IPS sensor running, applications have names; without it, traffic is
   counted under the remote organisation and port.

## Limits

- Traffic Flow sees only what the CPU processes: hardware-offloaded bridged
  traffic is invisible, and RouterOS documents that FastTrack packets bypass it
  (Preview warns about an active fasttrack rule).
- IPFIX over UDP can be lost; the page counts the records the sequence numbers
  say never arrived.
- Rates are a minute's average, not a peak.
