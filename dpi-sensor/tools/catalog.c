/*
 * catalog: what nDPI can name, as the JSON MikroDash's rule editor offers.
 *
 * The sensor and MikroDash must agree on every name: a rule matches the
 * strings the sensor sends, so the editor's lists are printed by the same
 * library the sensor links, not typed. Run it against the nDPI the sensor's
 * Dockerfile pins and write the result over internal/ips/ndpi_catalog.json:
 *
 *   cc -I<nDPI>/src/include -o catalog catalog.c <nDPI>/src/lib/libndpi.a -lm
 *   ./catalog > ../../internal/ips/ndpi_catalog.json
 */

#include <stdio.h>
#include <string.h>

#include "ndpi_api.h"

static void str(const char *s) {
  putchar('"');
  for (; *s; s++) {
    if (*s == '"' || *s == '\\') putchar('\\');
    putchar(*s);
  }
  putchar('"');
}

int main(void) {
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *m = ndpi_init_detection_module(NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(m, &all);
  ndpi_finalize_initialization(m);

  printf("{\n  \"ndpi\": ");
  str(ndpi_revision());
  printf(",\n  \"apps\": [");
  u_int n = ndpi_get_num_supported_protocols(m);
  int first = 1;
  for (u_int id = 1; id < n; id++) {
    const char *name = ndpi_get_proto_name(m, (u_int16_t)id);
    if (!name || !*name || !strcmp(name, "Unknown")) continue;
    ndpi_protocol p;
    memset(&p, 0, sizeof(p));
    p.proto.app_protocol = (u_int16_t)id;
    printf(first ? "\n    {\"name\": " : ",\n    {\"name\": ");
    first = 0;
    str(name);
    printf(", \"category\": ");
    str(ndpi_category_get_name(m, ndpi_get_proto_category(m, p)));
    printf(", \"breed\": ");
    str(ndpi_get_proto_breed_name(ndpi_get_proto_breed(m, (u_int16_t)id)));
    printf("}");
  }
  printf("\n  ],\n  \"categories\": [");
  first = 1;
  for (int c = 0; c < NDPI_PROTOCOL_NUM_CATEGORIES; c++) {
    const char *name = ndpi_category_get_name(m, (ndpi_protocol_category_t)c);
    if (!name || !*name || !strncmp(name, "User custom category", 20) || !strncmp(name, "Unspecified", 11)) continue;
    printf(first ? "\n    " : ",\n    ");
    first = 0;
    str(name);
  }
  printf("\n  ],\n  \"breeds\": [");
  first = 1;
  for (int b = 0; b <= NDPI_PROTOCOL_UNRATED; b++) {
    const char *name = ndpi_get_proto_breed_name((ndpi_protocol_breed_t)b);
    if (!name || !*name) continue;
    printf(first ? "\n    " : ",\n    ");
    first = 0;
    str(name);
  }
  printf("\n  ],\n  \"risks\": [");
  first = 1;
  for (int r = 1; r < NDPI_MAX_RISK; r++) {
    const char *name = ndpi_risk2str((ndpi_risk_enum)r);
    if (!name || !*name) continue;
    printf(first ? "\n    " : ",\n    ");
    first = 0;
    str(name);
  }
  printf("\n  ]\n}\n");
  ndpi_exit_detection_module(m);
  return 0;
}
