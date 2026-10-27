# syntax=docker/dockerfile:1
#
# mikrodash-dpi: the IPS page's sensor, built to run as a RouterOS container.
#
# ── STATIC, ON SCRATCH ──────────────────────────────────────────────────────
#
# A router's disk is small, so the image is one static binary and nothing else:
# nDPI is compiled as a static library against musl and linked in. The result
# is a few megabytes for every architecture RouterOS runs containers on.
#
# nDPI is pinned to a release tag, so a rebuild classifies the same way the
# last one did until the tag is moved here on purpose.

FROM alpine:3.24 AS build
ARG NDPI_REF=4.14
RUN apk add --no-cache build-base autoconf automake libtool pkgconf git linux-headers
RUN git clone --depth 1 --branch "$NDPI_REF" https://github.com/ntop/nDPI.git /ndpi
WORKDIR /ndpi
RUN ./autogen.sh --with-only-libndpi >/dev/null \
 && ./configure --with-only-libndpi --disable-shared >/dev/null \
 && make -j"$(nproc)" -C src/lib
COPY mikrodash-dpi.c /src/
RUN cc -O2 -Wall -Wextra -static -I/ndpi/src/include -o /mikrodash-dpi /src/mikrodash-dpi.c \
      /ndpi/src/lib/libndpi.a -lm \
 && strip /mikrodash-dpi \
 && /mikrodash-dpi --version

FROM scratch
COPY --from=build /mikrodash-dpi /mikrodash-dpi
# 37008/udp: TZSP from the router's mangle rule. 37009/tcp: MikroDash reads here.
EXPOSE 37008/udp 37009/tcp
ENTRYPOINT ["/mikrodash-dpi"]
