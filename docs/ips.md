# The IPS page

MikroDash can classify the traffic a MikroTik forwards with
[nDPI](https://github.com/ntop/nDPI) and act on it: log a flow, block the server
it reached, or quarantine the client that made it. The page is **Security -> IPS**.

```
router  mangle action=sniff-tzsp: the first bytes of each forwarded connection
   |    UDP 37008, TZSP
   v
mikrodash-dpi (a container on the router): nDPI, one JSON line per flow
   ^    TCP 37009, "HELLO <token>"
   |
MikroDash: the rules -> address lists -> raw drop rules on the router
```

## What it is, and what it is not

- **Detect, then block.** RouterOS forwards a packet whatever the sensor thinks of
  it, so this cannot be an inline IPS. A verdict becomes an address-list entry with
  a timeout, which raw rules drop. The first packets of the flow that was judged
  have already passed; the rest of that connection, and every later one, are
  dropped.
- **Blocking is by address.** `block` lists the server for every client; a service
  on a shared CDN takes its neighbours with it. `quarantine` lists the client, the
  precise answer to "this device should not be doing that".
- **IPv4.** The mangle rule copies IPv4, and the lists are IPv4 lists.
- **Fasttrack hides traffic.** A fasttracked connection leaves the mangle table
  after its first packets, often before the TLS ClientHello that names the service.
  The Setup tab's Preview warns and gives the change:
  `/ip/firewall/filter/set [find where action=fasttrack-connection] connection-bytes=20000-0`.

## Setting it up

1. **Containers.** Install the `container` package and, once, with physical access:
   `/system/device-mode/update container=yes`, then press the reset button or
   power-cycle. An external disk (`usb1`) is recommended.
2. **Setup tab: the sensor.** Give the container an address, the disk, and the
   addresses that must never be listed (your workstation, servers, resolvers). The
   router, MikroDash and the sensor are always protected. Leave **Enforce** off to
   start with. The address decides where the container lives:
   - **inside one of the router's networks** (`192.168.11.250` on a `192.168.11.1/24`
     bridge): it becomes a port of that bridge, with the network's VLAN as its `pvid`
     when the network is a VLAN on a VLAN-filtering bridge. Nothing else is created,
     and MikroDash reaches it directly;
   - **anywhere else**: it is the second address of a /30 of its own
     (`172.31.255.2`), with a bridge and the router's address on it.
3. **Show the commands**, and run them in the router's terminal. They create the
   veth, its bridge port (and, on a /30, the bridge and the router's address) and
   the container, with the token MikroDash will send. The image is `ghcr.io/jenubis78/mikrodash-dpi`, built
   by `.github/workflows/dpi-sensor.yml` on a `dpi-v*` tag.
4. **MikroDash must reach the sensor** at its address on TCP 37009. When MikroDash's
   host routes through this router, that works as it is. The header turns to
   `sensor up`.
5. **Preview, then Apply** writes one mangle rule and three raw rules, each
   commented `MikroDash IPS`. Remove takes them off and empties the two lists.
6. **Rules tab.** Start with `log` rules and read **Decisions**; the Applications tab
   lists the names nDPI uses. When the decisions are what you want, turn **Enforce**
   on.

## Safety

- Every listing is judged by `guard.CheckIPSTarget`, which refuses the router's own
  addresses, the addresses the router sees MikroDash from, the sensor, your
  protected list and special addresses, and refuses everything while the router's
  addresses cannot be read.
- At most sixty listings a minute per router; past that, decisions are recorded as
  `limited`.
- Every entry times out on its own (one minute to a week).
- Rule, sensor and router changes are for administrators, and are audited.
