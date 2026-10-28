/*
 * mikrodash-dpi: the IPS page's sensor. It classifies the traffic a MikroTik
 * copies to it with nDPI, and hands each classified flow to MikroDash.
 *
 * ── WHERE THE PACKETS COME FROM ──────────────────────────────────────────────
 *
 * A mangle rule on the router (`action=sniff-tzsp`) copies the first bytes of
 * every forwarded connection to this container as TZSP over UDP. TZSP is a
 * four-byte header, a list of tagged fields ending in tag 1, then the frame.
 * RouterOS sends Ethernet; a frame that starts with an IP version nibble is
 * taken as bare IP, which covers what a tunnel interface yields.
 *
 * ── ONE EVENT PER FLOW ──────────────────────────────────────────────────────
 *
 * A flow is fed to nDPI until nDPI says it is done (an application and no more
 * dissection to do), until it has seen DPI_MAX_PACKETS packets, or until it has
 * been idle for the timeout; then nDPI gives up and the flow is reported once.
 * Its nDPI state is freed at that point and only the key stays, so the rest of
 * a long connection costs a hash lookup and is never reported twice.
 *
 * ── HOW MIKRODASH READS IT ──────────────────────────────────────────────────
 *
 * MikroDash dials TCP DPI_LISTEN_PORT, sends `HELLO <token>\n`, and from then on
 * reads one JSON object a line: `hello`, then `flow` and `stats`. One reader at
 * a time; a new one that authenticates replaces the old. A reader that does not
 * keep up loses events, which are counted in `stats`, rather than slowing the
 * capture.
 *
 * ── LIVE VOLUMES, WHEN IT SEES EVERY PACKET ─────────────────────────────────
 *
 * A reader that sends `BYTES <seconds>\n` after the handshake (1 to 60; 0
 * stops) gets, that often, a `bytes` event: for every connection that moved
 * since the last one, the bytes its client sent (tx) and received (rx) in
 * between, as compact arrays [l4, client, clientPort, server, serverPort, tx,
 * rx], several hundred to a line. It is only worth asking when the router
 * copies every packet: from the first bytes alone the counts stop early. A
 * sensor before version 2 ignores the line.
 *
 * Configuration is by flag or environment: --token / DPI_TOKEN (required),
 * --tzsp-port / DPI_TZSP_PORT (37008), --listen-port / DPI_LISTEN_PORT (37009),
 * --max-flows / DPI_MAX_FLOWS (32768), --idle / DPI_IDLE_SECONDS (120).
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "ndpi_api.h"

#define SENSOR_VERSION "2"
#define DPI_MAX_PACKETS 32
#define HASH_BUCKETS (1u << 16)
#define OUT_CAP (1u << 20)
#define LINE_MAX_LEN 2048

/* ── configuration ─────────────────────────────────────────────────────── */

static const char *cfg_token;
static int cfg_tzsp_port = 37008;
static int cfg_listen_port = 37009;
static unsigned cfg_max_flows = 32768;
static unsigned cfg_idle_ms = 120000;
/* bytes_every_ms is how often the reader asked for live volumes; 0 is never. */
static uint64_t bytes_every_ms;
static uint64_t bytes_last_ms;

/* ── flows ─────────────────────────────────────────────────────────────── */

struct flow_key {
  uint8_t family, l4;
  uint8_t a[16], b[16]; /* the lower endpoint first, so both directions agree */
  uint16_t pa, pb;
};

struct flow {
  struct flow *hnext;
  struct flow *older, *newer; /* LRU, oldest at lru_old */
  struct flow_key key;
  uint8_t client_is_a;
  uint8_t done;
  struct ndpi_flow_struct *nf;
  uint64_t first_ms, last_ms;
  uint32_t packets;
  uint64_t bytes;
  uint64_t up, down; /* bytes the client sent and received since the last bytes event */
};

static struct ndpi_detection_module_struct *ndpi;
static struct flow *buckets[HASH_BUCKETS];
static struct flow *lru_old, *lru_new;
static unsigned nflows;

static struct {
  uint64_t packets, bytes, flows, reported, dropped_events, bad_frames, evicted;
} stats;

/* ── output to the one reader ──────────────────────────────────────────── */

static int reader_fd = -1;
/* What the reader has sent and not yet ended with a newline; reset for each reader. */
static char in[256];
static size_t in_len;
static void reader_lines(void);
static char *out_buf;
static size_t out_len;

static int pending_fd = -1;
static char pending_line[256];
static size_t pending_len;
static uint64_t pending_deadline;

static uint64_t now_mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint64_t now_wall_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void logf_(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "[mikrodash-dpi] ");
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
}

/* emit queues one line for the reader, or counts it lost. */
static void emit(const char *line, size_t n) {
  if (reader_fd < 0) return;
  if (out_len + n + 1 > OUT_CAP) {
    stats.dropped_events++;
    return;
  }
  memcpy(out_buf + out_len, line, n);
  out_len += n;
  out_buf[out_len++] = '\n';
}

static void drop_reader(void) {
  if (reader_fd >= 0) close(reader_fd);
  reader_fd = -1;
  out_len = 0;
}

static void flush_reader(void) {
  while (reader_fd >= 0 && out_len > 0) {
    ssize_t w = send(reader_fd, out_buf, out_len, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (w < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      if (errno == EINTR) continue;
      drop_reader();
      return;
    }
    memmove(out_buf, out_buf + w, out_len - (size_t)w);
    out_len -= (size_t)w;
  }
}

/* json_str appends a JSON string literal, escaped. */
static size_t json_str(char *dst, size_t cap, const char *s) {
  size_t n = 0;
  if (cap < 3) return 0;
  dst[n++] = '"';
  for (; *s && n + 7 < cap; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      dst[n++] = '\\';
      dst[n++] = (char)c;
    } else if (c < 0x20 || c >= 0x7f) {
      /* Hostnames and SNIs are ASCII; anything else is replaced, not trusted. */
      n += (size_t)snprintf(dst + n, cap - n, "\\u%04x", c < 0x20 ? c : '?');
    } else {
      dst[n++] = (char)c;
    }
  }
  dst[n++] = '"';
  dst[n] = 0;
  return n;
}

/* ── the flow table ────────────────────────────────────────────────────── */

static uint32_t key_hash(const struct flow_key *k) {
  const uint8_t *p = (const uint8_t *)k;
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < sizeof(*k); i++) h = (h ^ p[i]) * 16777619u;
  return h & (HASH_BUCKETS - 1);
}

static void lru_unlink(struct flow *f) {
  if (f->older) f->older->newer = f->newer; else lru_old = f->newer;
  if (f->newer) f->newer->older = f->older; else lru_new = f->older;
  f->older = f->newer = NULL;
}

static void lru_push(struct flow *f) {
  f->older = lru_new;
  f->newer = NULL;
  if (lru_new) lru_new->newer = f; else lru_old = f;
  lru_new = f;
}

static void addr_str(uint8_t family, const uint8_t *a, char *out, size_t cap) {
  inet_ntop(family == 4 ? AF_INET : AF_INET6, a, out, (socklen_t)cap);
}

static const char *l4_name(uint8_t l4) {
  switch (l4) {
  case IPPROTO_TCP: return "tcp";
  case IPPROTO_UDP: return "udp";
  case IPPROTO_ICMP: return "icmp";
  case IPPROTO_ICMPV6: return "icmpv6";
  default: return "other";
  }
}

/* report emits a flow's one event and frees its nDPI state. */
static void report(struct flow *f, ndpi_protocol proto, int gave_up) {
  char line[LINE_MAX_LEN], cli[INET6_ADDRSTRLEN], srv[INET6_ADDRSTRLEN], name[64];
  const uint8_t *ca = f->client_is_a ? f->key.a : f->key.b;
  const uint8_t *sa = f->client_is_a ? f->key.b : f->key.a;
  uint16_t cp = f->client_is_a ? f->key.pa : f->key.pb;
  uint16_t sp = f->client_is_a ? f->key.pb : f->key.pa;
  uint16_t upper = ndpi_get_upper_proto(proto);
  size_t n;

  addr_str(f->key.family, ca, cli, sizeof(cli));
  addr_str(f->key.family, sa, srv, sizeof(srv));
  ndpi_protocol2name(ndpi, proto, name, sizeof(name));

  n = (size_t)snprintf(line, sizeof(line),
                       "{\"type\":\"flow\",\"ts\":%llu,\"l4\":\"%s\",\"client\":\"%s\",\"clientPort\":%u,"
                       "\"server\":\"%s\",\"serverPort\":%u,\"name\":",
                       (unsigned long long)(now_wall_ms() - (now_mono_ms() - f->first_ms)), l4_name(f->key.l4),
                       cli, cp, srv, sp);
  n += json_str(line + n, sizeof(line) - n, name);
  n += (size_t)snprintf(line + n, sizeof(line) - n, ",\"app\":");
  n += json_str(line + n, sizeof(line) - n, ndpi_get_proto_name(ndpi, upper));
  n += (size_t)snprintf(line + n, sizeof(line) - n, ",\"master\":");
  n += json_str(line + n, sizeof(line) - n, ndpi_get_proto_name(ndpi, proto.proto.master_protocol));
  n += (size_t)snprintf(line + n, sizeof(line) - n, ",\"category\":");
  n += json_str(line + n, sizeof(line) - n, ndpi_category_get_name(ndpi, proto.category));
  n += (size_t)snprintf(line + n, sizeof(line) - n, ",\"breed\":");
  n += json_str(line + n, sizeof(line) - n, ndpi_get_proto_breed_name(ndpi_get_proto_breed(ndpi, upper)));
  n += (size_t)snprintf(line + n, sizeof(line) - n, ",\"host\":");
  n += json_str(line + n, sizeof(line) - n, f->nf ? f->nf->host_server_name : "");
  n += (size_t)snprintf(line + n, sizeof(line) - n, ",\"risks\":[");
  if (f->nf) {
    int first = 1;
    for (int r = 1; r < NDPI_MAX_RISK && n + 100 < sizeof(line); r++) {
      if (!(f->nf->risk & (1ULL << r))) continue;
      if (!first) line[n++] = ',';
      first = 0;
      n += json_str(line + n, sizeof(line) - n, ndpi_risk2str((ndpi_risk_enum)r));
    }
  }
  n += (size_t)snprintf(line + n, sizeof(line) - n, "],\"guessed\":%s,\"packets\":%u,\"bytes\":%llu}",
                        gave_up ? "true" : "false", f->packets, (unsigned long long)f->bytes);
  if (n < sizeof(line)) emit(line, n);
  stats.reported++;

  if (f->nf) ndpi_free_flow(f->nf);
  f->nf = NULL;
  f->done = 1;
}

static void giveup(struct flow *f) {
  uint8_t guessed = 0;
  ndpi_protocol p = ndpi_detection_giveup(ndpi, f->nf, &guessed);
  report(f, p, 1);
}

static void flow_free(struct flow *f) {
  uint32_t h = key_hash(&f->key);
  struct flow **pp = &buckets[h];
  while (*pp && *pp != f) pp = &(*pp)->hnext;
  if (*pp) *pp = f->hnext;
  lru_unlink(f);
  if (f->nf) ndpi_free_flow(f->nf);
  free(f);
  nflows--;
}

/* expire reports and forgets what has been idle past the timeout. */
static void expire(uint64_t now) {
  while (lru_old && now - lru_old->last_ms >= cfg_idle_ms) {
    struct flow *f = lru_old;
    if (!f->done && f->nf && f->packets > 0) giveup(f);
    flow_free(f);
  }
}

static struct flow *flow_get(const struct flow_key *k, uint64_t now, int *created) {
  uint32_t h = key_hash(k);
  struct flow *f;
  for (f = buckets[h]; f; f = f->hnext)
    if (memcmp(&f->key, k, sizeof(*k)) == 0) return f;
  if (nflows >= cfg_max_flows && lru_old) {
    stats.evicted++;
    if (!lru_old->done && lru_old->nf && lru_old->packets > 0) giveup(lru_old);
    flow_free(lru_old);
  }
  f = calloc(1, sizeof(*f));
  if (!f) return NULL;
  f->nf = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
  if (!f->nf) {
    free(f);
    return NULL;
  }
  memset(f->nf, 0, SIZEOF_FLOW_STRUCT);
  f->key = *k;
  f->first_ms = now;
  f->hnext = buckets[h];
  buckets[h] = f;
  lru_push(f);
  nflows++;
  stats.flows++;
  *created = 1;
  return f;
}

/* ── packets ───────────────────────────────────────────────────────────── */

struct pkt {
  const uint8_t *l3;
  uint16_t l3_len;
  uint8_t family, l4;
  const uint8_t *src, *dst;
  uint16_t sport, dport;
  uint8_t tcp_flags;
};

static int parse_l4(struct pkt *p, const uint8_t *l4, size_t len) {
  if (p->l4 == IPPROTO_TCP) {
    if (len < 20) return -1;
    p->sport = (uint16_t)(l4[0] << 8 | l4[1]);
    p->dport = (uint16_t)(l4[2] << 8 | l4[3]);
    p->tcp_flags = l4[13];
  } else if (p->l4 == IPPROTO_UDP) {
    if (len < 8) return -1;
    p->sport = (uint16_t)(l4[0] << 8 | l4[1]);
    p->dport = (uint16_t)(l4[2] << 8 | l4[3]);
  }
  return 0;
}

static int parse_ip(struct pkt *p, const uint8_t *b, size_t len) {
  if (len < 1) return -1;
  if ((b[0] >> 4) == 4) {
    size_t ihl = (size_t)(b[0] & 0x0f) * 4, total;
    if (len < 20 || ihl < 20 || len < ihl) return -1;
    total = (size_t)(b[2] << 8 | b[3]);
    if (total < ihl) return -1;
    if (total > len) total = len; /* a capture shorter than the packet */
    p->family = 4;
    p->l4 = b[9];
    p->src = b + 12;
    p->dst = b + 16;
    p->l3 = b;
    p->l3_len = (uint16_t)total;
    if ((b[6] & 0x1f) != 0 || b[7] != 0) return 0; /* a non-first fragment: no ports */
    return parse_l4(p, b + ihl, total - ihl);
  }
  if ((b[0] >> 4) == 6) {
    size_t off = 40, total;
    uint8_t nh;
    if (len < 40) return -1;
    total = 40 + (size_t)(b[4] << 8 | b[5]);
    if (total > len) total = len;
    if (total > 65535) total = 65535;
    p->family = 6;
    p->src = b + 8;
    p->dst = b + 24;
    p->l3 = b;
    p->l3_len = (uint16_t)total;
    nh = b[6];
    /* Hop-by-hop, routing and destination options are walked; a fragment
     * header or anything else ends the walk with no ports. */
    while ((nh == 0 || nh == 43 || nh == 60) && off + 8 <= total) {
      nh = b[off];
      off += 8 + (size_t)b[off + 1] * 8;
    }
    p->l4 = nh;
    if (off > total) return -1;
    return parse_l4(p, b + off, total - off);
  }
  return -1;
}

/* parse_tzsp finds the IP packet inside one TZSP datagram. */
static int parse_tzsp(struct pkt *p, const uint8_t *b, size_t len) {
  size_t off = 4;
  uint16_t encap, ethertype;
  if (len < 5 || b[0] != 1) return -1;
  encap = (uint16_t)(b[2] << 8 | b[3]);
  while (off < len) {
    uint8_t tag = b[off];
    if (tag == 1) { off++; break; }
    if (tag == 0) { off++; continue; }
    if (off + 2 > len) return -1;
    off += 2 + b[off + 1];
  }
  if (off >= len) return -1;
  b += off;
  len -= off;
  /* Not Ethernet, or Ethernet that does not hold IP: try it as bare IP. */
  if (encap != 1) return parse_ip(p, b, len);
  if (len < 14) return parse_ip(p, b, len);
  ethertype = (uint16_t)(b[12] << 8 | b[13]);
  off = 14;
  while ((ethertype == 0x8100 || ethertype == 0x88a8) && len >= off + 4) {
    ethertype = (uint16_t)(b[off + 2] << 8 | b[off + 3]);
    off += 4;
  }
  if (ethertype == 0x8864 && len >= off + 8) { /* PPPoE session: PPP protocol 0x21 / 0x57 */
    uint16_t ppp = (uint16_t)(b[off + 6] << 8 | b[off + 7]);
    if (ppp != 0x0021 && ppp != 0x0057) return -1;
    off += 8;
    ethertype = ppp == 0x0021 ? 0x0800 : 0x86dd;
  }
  if (ethertype != 0x0800 && ethertype != 0x86dd) return parse_ip(p, b, len);
  return parse_ip(p, b + off, len - off);
}

static int endpoint_cmp(const uint8_t *a, uint16_t pa, const uint8_t *b, uint16_t pb, size_t alen) {
  int c = memcmp(a, b, alen);
  if (c) return c;
  return (int)pa - (int)pb;
}

static void handle_packet(const uint8_t *b, size_t len) {
  struct pkt p;
  struct flow_key k;
  struct flow *f;
  size_t alen;
  int created = 0, src_is_a;
  uint64_t now = now_mono_ms();

  memset(&p, 0, sizeof(p));
  if (parse_tzsp(&p, b, len) != 0) {
    stats.bad_frames++;
    return;
  }
  stats.packets++;
  stats.bytes += p.l3_len;

  memset(&k, 0, sizeof(k));
  alen = p.family == 4 ? 4 : 16;
  k.family = p.family;
  k.l4 = p.l4;
  src_is_a = endpoint_cmp(p.src, p.sport, p.dst, p.dport, alen) <= 0;
  memcpy(k.a, src_is_a ? p.src : p.dst, alen);
  memcpy(k.b, src_is_a ? p.dst : p.src, alen);
  k.pa = src_is_a ? p.sport : p.dport;
  k.pb = src_is_a ? p.dport : p.sport;

  f = flow_get(&k, now, &created);
  if (!f) return;
  if (created) {
    /* Who opened it: a SYN says so outright; otherwise the well-known port is
     * the server's, and failing that the first packet seen is the client's. */
    int src_client = 1;
    if (p.l4 == IPPROTO_TCP && (p.tcp_flags & 0x02)) src_client = !(p.tcp_flags & 0x10);
    else if (p.sport < 1024 && p.dport >= 1024) src_client = 0;
    f->client_is_a = (uint8_t)(src_client ? src_is_a : !src_is_a);
  }
  f->last_ms = now;
  f->packets++;
  f->bytes += p.l3_len;
  if (src_is_a == f->client_is_a) f->up += p.l3_len;
  else f->down += p.l3_len;
  lru_unlink(f);
  lru_push(f);
  if (f->done || !f->nf) return;

  ndpi_protocol proto = ndpi_detection_process_packet(ndpi, f->nf, p.l3, p.l3_len, now, NULL);
  int known = proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN || proto.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN;
  if (known && !ndpi_extra_dissection_possible(ndpi, f->nf)) report(f, proto, 0);
  else if (f->packets >= DPI_MAX_PACKETS) giveup(f);
}

/* ── the reader's socket ───────────────────────────────────────────────── */

static int token_ok(const char *got) {
  size_t a = strlen(got), b = strlen(cfg_token);
  unsigned char diff = (unsigned char)(a != b);
  for (size_t i = 0; i < a; i++) diff |= (unsigned char)(got[i] ^ cfg_token[i % (b ? b : 1)]);
  return diff == 0;
}

static void accept_pending(int lfd) {
  int fd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
  if (fd < 0) return;
  if (pending_fd >= 0) close(pending_fd); /* one handshake at a time */
  pending_fd = fd;
  pending_len = 0;
  pending_deadline = now_mono_ms() + 5000;
}

static void read_pending(void) {
  ssize_t r = recv(pending_fd, pending_line + pending_len, sizeof(pending_line) - 1 - pending_len, 0);
  char *nl;
  if (r <= 0) {
    if (r < 0 && (errno == EAGAIN || errno == EINTR)) return;
    close(pending_fd);
    pending_fd = -1;
    return;
  }
  pending_len += (size_t)r;
  pending_line[pending_len] = 0;
  nl = strchr(pending_line, '\n');
  if (!nl) {
    if (pending_len >= sizeof(pending_line) - 1) {
      close(pending_fd);
      pending_fd = -1;
    }
    return;
  }
  *nl = 0;
  if (nl > pending_line && nl[-1] == '\r') nl[-1] = 0;
  if (strncmp(pending_line, "HELLO ", 6) != 0 || !token_ok(pending_line + 6)) {
    const char *no = "{\"type\":\"error\",\"message\":\"bad token\"}\n";
    (void)!send(pending_fd, no, strlen(no), MSG_NOSIGNAL | MSG_DONTWAIT);
    close(pending_fd);
    pending_fd = -1;
    logf_("a reader was refused: bad token");
    return;
  }
  drop_reader();
  reader_fd = pending_fd;
  pending_fd = -1;
  bytes_every_ms = 0; /* each reader asks for itself */
  /* What came in behind the HELLO line is the reader's first requests. */
  {
    char *rest = nl + 1;
    size_t left = pending_len - (size_t)(rest - pending_line);
    if (left >= sizeof(in)) left = 0;
    memcpy(in, rest, left);
    in_len = left;
    in[in_len] = 0;
  }
  char hello[160];
  int n = snprintf(hello, sizeof(hello), "{\"type\":\"hello\",\"version\":\"%s\",\"ndpi\":\"%s\"}", SENSOR_VERSION,
                   ndpi_revision());
  emit(hello, (size_t)n);
  logf_("a reader connected");
  reader_lines();
}

/* emit_bytes sends what every connection moved since the last call, newest
 * first, and stops at the first that has not moved since. */
static void emit_bytes(uint64_t now) {
  static char line[16384];
  char cli[INET6_ADDRSTRLEN], srv[INET6_ADDRSTRLEN];
  size_t n = 0;
  int count = 0;
  for (struct flow *f = lru_new; f && f->last_ms >= bytes_last_ms; f = f->older) {
    if (!f->up && !f->down) continue;
    const uint8_t *ca = f->client_is_a ? f->key.a : f->key.b;
    const uint8_t *sa = f->client_is_a ? f->key.b : f->key.a;
    addr_str(f->key.family, ca, cli, sizeof(cli));
    addr_str(f->key.family, sa, srv, sizeof(srv));
    if (n == 0) n = (size_t)snprintf(line, sizeof(line), "{\"type\":\"bytes\",\"f\":[");
    n += (size_t)snprintf(line + n, sizeof(line) - n, "%s[\"%s\",\"%s\",%u,\"%s\",%u,%llu,%llu]", count ? "," : "",
                          l4_name(f->key.l4), cli, f->client_is_a ? f->key.pa : f->key.pb, srv,
                          f->client_is_a ? f->key.pb : f->key.pa, (unsigned long long)f->up,
                          (unsigned long long)f->down);
    f->up = f->down = 0;
    count++;
    if (n + 200 > sizeof(line)) {
      n += (size_t)snprintf(line + n, sizeof(line) - n, "]}");
      emit(line, n);
      n = 0;
      count = 0;
    }
  }
  if (n) {
    n += (size_t)snprintf(line + n, sizeof(line) - n, "]}");
    emit(line, n);
  }
  bytes_last_ms = now;
}

/* read_reader takes the reader's requests: today, `BYTES <seconds>`. */
static void read_reader(void) {
  ssize_t r = recv(reader_fd, in + in_len, sizeof(in) - 1 - in_len, MSG_DONTWAIT);
  if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR)) {
    drop_reader();
    in_len = 0;
    logf_("the reader went away");
    return;
  }
  if (r < 0) return;
  in_len += (size_t)r;
  in[in_len] = 0;
  reader_lines();
}

/* reader_lines acts on each whole line the reader has sent. */
static void reader_lines(void) {
  char *nl;
  while ((nl = strchr(in, '\n'))) {
    *nl = 0;
    unsigned secs;
    if (sscanf(in, "BYTES %u", &secs) == 1 && secs <= 60) {
      bytes_every_ms = (uint64_t)secs * 1000;
      bytes_last_ms = now_mono_ms();
      if (secs) logf_("live volumes every %u s", secs);
      else logf_("live volumes off");
    }
    size_t used = (size_t)(nl - in) + 1;
    memmove(in, nl + 1, in_len - used + 1);
    in_len -= used;
  }
  if (in_len >= sizeof(in) - 1) in_len = 0; /* a line too long is nonsense: dropped */
}

static void emit_stats(void) {
  char line[400];
  int n = snprintf(line, sizeof(line),
                   "{\"type\":\"stats\",\"packets\":%llu,\"bytes\":%llu,\"flows\":%llu,\"active\":%u,"
                   "\"reported\":%llu,\"droppedEvents\":%llu,\"badFrames\":%llu,\"evicted\":%llu}",
                   (unsigned long long)stats.packets, (unsigned long long)stats.bytes,
                   (unsigned long long)stats.flows, nflows, (unsigned long long)stats.reported,
                   (unsigned long long)stats.dropped_events, (unsigned long long)stats.bad_frames,
                   (unsigned long long)stats.evicted);
  emit(line, (size_t)n);
}

/* ── setup ─────────────────────────────────────────────────────────────── */

/* bind_socket listens on both families where the host has IPv6, and on IPv4
 * alone where it has not, which a container on a router often has not. */
static int bind_socket(int type, int port) {
  int fd = socket(AF_INET6, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0), on = 1, off = 0, ok;
  if (fd >= 0) {
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_any;
    sa.sin6_port = htons((uint16_t)port);
    if (type == SOCK_STREAM) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    ok = bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
  } else {
    struct sockaddr_in sa;
    fd = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)port);
    if (type == SOCK_STREAM) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    ok = bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
  }
  if (!ok || (type == SOCK_STREAM && listen(fd, 4) != 0)) {
    close(fd);
    return -1;
  }
  if (type == SOCK_DGRAM) {
    int sz = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
  }
  return fd;
}

static int int_opt(const char *v, int lo, int hi, const char *what) {
  char *end;
  long n = strtol(v ? v : "", &end, 10);
  if (!v || *end || n < lo || n > hi) {
    logf_("%s must be a number from %d to %d", what, lo, hi);
    exit(2);
  }
  return (int)n;
}

static void configure(int argc, char **argv) {
  const char *e;
  if ((e = getenv("DPI_TOKEN")) && *e) cfg_token = e;
  if ((e = getenv("DPI_TZSP_PORT")) && *e) cfg_tzsp_port = int_opt(e, 1, 65535, "DPI_TZSP_PORT");
  if ((e = getenv("DPI_LISTEN_PORT")) && *e) cfg_listen_port = int_opt(e, 1, 65535, "DPI_LISTEN_PORT");
  if ((e = getenv("DPI_MAX_FLOWS")) && *e) cfg_max_flows = (unsigned)int_opt(e, 1024, 1 << 22, "DPI_MAX_FLOWS");
  if ((e = getenv("DPI_IDLE_SECONDS")) && *e) cfg_idle_ms = (unsigned)int_opt(e, 10, 3600, "DPI_IDLE_SECONDS") * 1000;
  for (int i = 1; i < argc; i++) {
    const char *v = i + 1 < argc ? argv[i + 1] : NULL;
    if (!strcmp(argv[i], "--token") && v) cfg_token = argv[++i];
    else if (!strcmp(argv[i], "--tzsp-port")) cfg_tzsp_port = int_opt(argv[++i], 1, 65535, "--tzsp-port");
    else if (!strcmp(argv[i], "--listen-port")) cfg_listen_port = int_opt(argv[++i], 1, 65535, "--listen-port");
    else if (!strcmp(argv[i], "--max-flows")) cfg_max_flows = (unsigned)int_opt(argv[++i], 1024, 1 << 22, "--max-flows");
    else if (!strcmp(argv[i], "--idle")) cfg_idle_ms = (unsigned)int_opt(argv[++i], 10, 3600, "--idle") * 1000;
    else if (!strcmp(argv[i], "--version")) {
      printf("mikrodash-dpi %s (nDPI %s)\n", SENSOR_VERSION, ndpi_revision());
      exit(0);
    } else {
      logf_("unknown argument %s", argv[i]);
      exit(2);
    }
  }
  if (!cfg_token || strlen(cfg_token) < 16) {
    logf_("a token of at least 16 characters is required (--token or DPI_TOKEN)");
    exit(2);
  }
}

static volatile sig_atomic_t stopping;
static void on_signal(int sig) { (void)sig; stopping = 1; }

int main(int argc, char **argv) {
  NDPI_PROTOCOL_BITMASK all;
  int ufd, lfd;
  uint64_t next_stats, next_expire;
  static uint8_t dgram[65536];

  configure(argc, argv);
  signal(SIGTERM, on_signal);
  signal(SIGINT, on_signal);
  signal(SIGPIPE, SIG_IGN);

  ndpi = ndpi_init_detection_module(NULL);
  if (!ndpi) {
    logf_("nDPI did not initialise");
    return 1;
  }
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi, &all);
  if (ndpi_finalize_initialization(ndpi) != 0) {
    logf_("nDPI did not finalise");
    return 1;
  }
  out_buf = malloc(OUT_CAP);
  ufd = bind_socket(SOCK_DGRAM, cfg_tzsp_port);
  lfd = bind_socket(SOCK_STREAM, cfg_listen_port);
  if (!out_buf || ufd < 0 || lfd < 0) {
    logf_("cannot listen on udp/%d and tcp/%d: %s", cfg_tzsp_port, cfg_listen_port, strerror(errno));
    return 1;
  }
  logf_("nDPI %s; TZSP on udp/%d, readers on tcp/%d", ndpi_revision(), cfg_tzsp_port, cfg_listen_port);

  next_stats = now_mono_ms() + 5000;
  next_expire = now_mono_ms() + 1000;
  while (!stopping) {
    struct pollfd pf[4];
    int n = 0, iu, il, ip = -1, ir = -1;
    iu = n; pf[n].fd = ufd; pf[n++].events = POLLIN;
    il = n; pf[n].fd = lfd; pf[n++].events = POLLIN;
    if (pending_fd >= 0) { ip = n; pf[n].fd = pending_fd; pf[n++].events = POLLIN; }
    if (reader_fd >= 0) {
      ir = n;
      pf[n].fd = reader_fd;
      pf[n++].events = (short)(POLLIN | (out_len ? POLLOUT : 0));
    }
    if (poll(pf, (nfds_t)n, 250) < 0 && errno != EINTR) break;

    if (pf[iu].revents & POLLIN) {
      /* Drain what is queued, bounded so the readers are not starved. */
      for (int i = 0; i < 4096; i++) {
        ssize_t r = recv(ufd, dgram, sizeof(dgram), 0);
        if (r <= 0) break;
        handle_packet(dgram, (size_t)r);
      }
    }
    if (pf[il].revents & POLLIN) accept_pending(lfd);
    if (ip >= 0 && pf[ip].revents) read_pending();
    if (ir >= 0 && (pf[ir].revents & (POLLIN | POLLHUP | POLLERR))) read_reader();

    uint64_t now = now_mono_ms();
    if (pending_fd >= 0 && now > pending_deadline) {
      close(pending_fd);
      pending_fd = -1;
    }
    if (now >= next_expire) {
      expire(now);
      next_expire = now + 1000;
    }
    if (now >= next_stats) {
      emit_stats();
      next_stats = now + 5000;
    }
    if (bytes_every_ms && reader_fd >= 0 && now - bytes_last_ms >= bytes_every_ms) emit_bytes(now);
    flush_reader();
  }
  logf_("stopping");
  return 0;
}
