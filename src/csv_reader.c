#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include "packet_record.h"

#define LINE_MAX_LEN   16384
#define HOUR_PM_CUTOFF 8   /* heure < 8 => apres-midi (pas d'AM/PM dans le CSV) */

/* Motifs de rejet (pour le diagnostic) */
enum {
    R_OK = 0, R_NO_LABEL, R_FEW_FIELDS, R_SRC_IP, R_DST_IP,
    R_NUMERIC, R_RANGE, R_TIMESTAMP, R_EMPTY_LABEL, R_TOO_MANY_LABELS,
    R_COUNT
};
static const char *reason_names[R_COUNT] = {
    "ok", "pas de label", "champs manquants", "IP source invalide",
    "IP destination invalide", "champ numerique invalide",
    "valeur hors plage", "timestamp invalide", "label vide",
    "trop de labels"
};

void dataset_init(Dataset *ds) { memset(ds, 0, sizeof(*ds)); }
void dataset_free(Dataset *ds) { free(ds->records); memset(ds, 0, sizeof(*ds)); }

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        *--e = '\0';
    return s;
}

static int parse_ipv4(const char *s, uint32_t *out) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return 0;
    *out = ntohl(a.s_addr);
    return 1;
}

/* Accepte entiers et decimaux (ex: "12", "12.0", "1.2E7"), valeurs >= 0 */
static int parse_u64(const char *s, unsigned long long *out) {
    if (*s < '0' || *s > '9') return 0;          /* refuse vide, '-', nan, inf */
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    if (*end != '\0' || errno) return 0;
    if (!(v >= 0.0 && v < 1.8e19)) return 0;     /* refuse NaN / inf / trop grand */
    *out = (unsigned long long)v;
    return 1;
}

/* Format du dataset : JJ/MM/AAAA H:MM (secondes optionnelles) */
static int parse_timestamp(const char *s, int64_t *out_ms) {
    int d, mo, y, h, mi, sec = 0;
    int n = sscanf(s, "%d/%d/%d %d:%d:%d", &d, &mo, &y, &h, &mi, &sec);
    if (n < 5) return 0;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || y < 1970 ||
        h < 0 || h > 23 || mi < 0 || mi > 59 || sec < 0 || sec > 59) return 0;


    /* Le dataset n'a aucun trafic avant 8h : une heure < 8 signifie l'apres-midi
       (convention 12h sans AM/PM), avec ou sans secondes. */
    if (h < HOUR_PM_CUTOFF) h += 12;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = y - 1900; tm.tm_mon = mo - 1; tm.tm_mday = d;
    tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = sec;
    time_t t = timegm(&tm);
    if (t == (time_t)-1) return 0;
    *out_ms = (int64_t)t * 1000;
    return 1;
}

static int label_id(Dataset *ds, const char *name) {
    for (int i = 0; i < ds->n_labels; i++)
        if (strcmp(ds->label_names[i], name) == 0) return i;
    if (ds->n_labels >= MAX_LABELS) return -1;
    strncpy(ds->label_names[ds->n_labels], name, LABEL_LEN - 1);
    return ds->n_labels++;
}

/* Retourne R_OK si la ligne est valide, sinon le motif de rejet. */
static int parse_line(char *line, Dataset *ds, PacketRecord *r) {
    char *last = strrchr(line, ',');
    if (!last) return R_NO_LABEL;
    char *label = trim(last + 1);
    *last = '\0';

    /* Normalisation du label : octets non ASCII -> '-' */
    for (char *c = label; *c; c++)
        if ((unsigned char)*c > 127) *c = '-';

    char *f[12];
    char *p = line;
    for (int i = 0; i < 12; i++) {
        char *c = strchr(p, ',');
        if (c) *c = '\0';
        else if (i < 11) return R_FEW_FIELDS;
        f[i] = trim(p);
        if (c) p = c + 1;
    }

    unsigned long long sp, dp, proto, fwd, bwd, lf, lb;
    if (!parse_ipv4(f[1], &r->src_ip)) return R_SRC_IP;
    if (!parse_ipv4(f[3], &r->dst_ip)) return R_DST_IP;
    if (!parse_u64(f[2], &sp) || !parse_u64(f[4], &dp) || !parse_u64(f[5], &proto) ||
        !parse_u64(f[8], &fwd) || !parse_u64(f[9], &bwd) ||
        !parse_u64(f[10], &lf) || !parse_u64(f[11], &lb)) return R_NUMERIC;
    if (sp > 65535 || dp > 65535 || proto > 255) return R_RANGE;
    if (!parse_timestamp(f[6], &r->timestamp_ms)) return R_TIMESTAMP;
    if (*label == '\0') return R_EMPTY_LABEL;
    int lid = label_id(ds, label);
    if (lid < 0) return R_TOO_MANY_LABELS;

    r->protocol   = (uint8_t)proto;
    r->has_ports  = (proto == PROTO_TCP || proto == PROTO_UDP);
    r->src_port   = r->has_ports ? (uint16_t)sp : 0;
    r->dst_port   = r->has_ports ? (uint16_t)dp : 0;
    r->packets    = (uint32_t)(fwd + bwd);
    r->size_bytes = lf + lb;
    r->label      = (uint8_t)lid;
    return R_OK;
}

int load_csv(const char *path, Dataset *ds) {
    FILE *fp = fopen(path, "r");
    if (!fp) { perror(path); return -1; }

    const int debug = getenv("DEBUG_INVALID") != NULL;
    size_t reasons[R_COUNT] = {0};
    int shown = 0;

    char line[LINE_MAX_LEN];
    char copy[512];
    int first = 1;

    while (fgets(line, sizeof(line), fp)) {
        if (first) { first = 0; continue; }          /* en-tete */
        ds->lines_read++;

        /* ligne trop longue : on la jette */
        if (!strchr(line, '\n') && !feof(fp)) {
            int ch;
            while ((ch = fgetc(fp)) != '\n' && ch != EOF) {}
            ds->invalid++;
            continue;
        }

        /* lignes vides ou composees uniquement de virgules/espaces */
        if (strspn(line, ", \t\r\n") == strlen(line)) { ds->blank++; continue; }

        if (ds->count == ds->capacity) {
            size_t ncap = ds->capacity ? ds->capacity * 2 : 1 << 20;
            PacketRecord *nr = realloc(ds->records, ncap * sizeof(PacketRecord));
            if (!nr) { fprintf(stderr, "Memoire insuffisante\n"); fclose(fp); return -1; }
            ds->records = nr;
            ds->capacity = ncap;
        }

        if (debug) { strncpy(copy, line, sizeof(copy) - 1); copy[sizeof(copy) - 1] = '\0'; }

        int reason = parse_line(line, ds, &ds->records[ds->count]);
        if (reason == R_OK) {
            ds->count++;
        } else {
            ds->invalid++;
            reasons[reason]++;
            if (debug && shown < 3) {
                fprintf(stderr, "INVALIDE (%s): %.300s\n", reason_names[reason], copy);
                shown++;
            }
        }
    }
    fclose(fp);

    if (debug) {
        fprintf(stderr, "--- Motifs de rejet pour %s ---\n", path);
        for (int i = 1; i < R_COUNT; i++)
            if (reasons[i]) fprintf(stderr, "  %-28s %zu\n", reason_names[i], reasons[i]);
    }
    return 0;
}
