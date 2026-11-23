#ifndef PACKET_RECORD_H
#define PACKET_RECORD_H

#include <stdint.h>
#include <stddef.h>

#define PROTO_ICMP 1
#define PROTO_TCP  6
#define PROTO_UDP  17

#define MAX_LABELS 32
#define LABEL_LEN  48

typedef struct {
    int64_t  timestamp_ms;   /* epoch UTC (heure du dataset, sans fuseau) */
    uint64_t size_bytes;     /* fwd + bwd bytes du flux */
    uint32_t src_ip;         /* ordre hote */
    uint32_t dst_ip;
    uint32_t packets;        /* fwd + bwd packets du flux */
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  has_ports;      /* 1 si TCP/UDP */
    uint8_t  label;          /* index dans label_names */
} PacketRecord;

typedef struct {
    PacketRecord *records;
    size_t count, capacity;
    size_t lines_read, invalid, blank;
    char   label_names[MAX_LABELS][LABEL_LEN];
    int    n_labels;
} Dataset;

void dataset_init(Dataset *ds);
void dataset_free(Dataset *ds);
int  load_csv(const char *path, Dataset *ds);   /* 0 = OK, -1 = erreur */

#endif
