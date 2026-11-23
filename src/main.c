#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <omp.h>
#include "analyzer.h"
#include "detection.h"

#define SPIKE_BASELINE  10
#define SPIKE_MIN_FLOWS 100
#define SPIKE_MIN_BYTES (1ULL << 20)
#define ULL(x) ((unsigned long long)(x))
#define MAX_LIST 16

typedef struct {
    int64_t  t_origin, window_ms;
    size_t   n_windows;
    unsigned scan_thr;
    double   spike_factor;
    int      scan_label;
} Params;

typedef struct {
    Stats    *s;
    AlertList al;
    double    t_analysis, t_detect;
} RunResult;

typedef struct { uint64_t stats, alerts; size_t n_alerts; } Ref;

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static const char *sched_name(void) {
    omp_sched_t k;
    int chunk;
    omp_get_schedule(&k, &chunk);
    switch ((int)k & 0xff) {
        case 1: return "static";
        case 2: return "dynamic";
        case 3: return "guided";
        case 4: return "auto";
        default: return "?";
    }
}

static Params make_params(const Dataset *ds, int window_s, unsigned scan_thr, double spike_factor) {
    int64_t tmin = ds->records[0].timestamp_ms, tmax = tmin;
    for (size_t i = 1; i < ds->count; i++) {
        if (ds->records[i].timestamp_ms < tmin) tmin = ds->records[i].timestamp_ms;
        if (ds->records[i].timestamp_ms > tmax) tmax = ds->records[i].timestamp_ms;
    }
    Params p;
    p.window_ms    = (int64_t)window_s * 1000;
    p.t_origin     = tmin - (tmin % p.window_ms);          /* fenetres alignees */
    p.n_windows    = (size_t)((tmax - p.t_origin) / p.window_ms) + 1;
    p.scan_thr     = scan_thr;
    p.spike_factor = spike_factor;
    p.scan_label   = -1;
    for (int i = 0; i < ds->n_labels; i++)
        if (!strcmp(ds->label_names[i], "PortScan")) p.scan_label = i;
    return p;
}

static void run_once(const Dataset *ds, const Params *p, int parallel, int threads,
                     RunResult *r) {
    r->s = stats_create(p->t_origin, p->window_ms, p->n_windows);

    double t1 = now_s();
    if (parallel) analyze_parallel(ds, r->s, threads);
    else          analyze_sequential(ds, r->s);
    r->t_analysis = now_s() - t1;

    alerts_init(&r->al);
    double t2 = now_s();
    if (parallel)
        detect_port_scans_parallel(ds, p->t_origin, p->window_ms, p->scan_thr,
                                   p->scan_label, threads, &r->al);
    else
        detect_port_scans(ds, p->t_origin, p->window_ms, p->scan_thr,
                          p->scan_label, 0, 1, &r->al);
    detect_spikes(r->s, r->s->win_flows, ALERT_SPIKE_FLOWS, SPIKE_BASELINE,
                  p->spike_factor, SPIKE_MIN_FLOWS, &r->al);
    detect_spikes(r->s, r->s->win_bytes, ALERT_SPIKE_BYTES, SPIKE_BASELINE,
                  p->spike_factor, SPIKE_MIN_BYTES, &r->al);
    alerts_sort(&r->al);
    r->t_detect = now_s() - t2;
}

static void free_run(RunResult *r) {
    stats_destroy(r->s);
    alerts_free(&r->al);
    r->s = NULL;
}

static void print_run(const char *name, const RunResult *r, size_t n) {
    double tot = r->t_analysis + r->t_detect;
    printf("%s\n", name);
    printf("  Analyse          : %.4f s  (%.0f flux/s)\n", r->t_analysis, n / r->t_analysis);
    printf("  Detection        : %.4f s  (%.0f flux/s)\n", r->t_detect, n / r->t_detect);
    printf("  Total            : %.4f s  (%.0f flux/s)\n", tot, n / tot);
    printf("  Checksum stats   : %016llx\n", ULL(stats_checksum(r->s)));
    printf("  Checksum alertes : %016llx (%zu alertes)\n",
           ULL(alerts_checksum(&r->al)), r->al.n);
}

/* ---------- benchmark ---------- */

/* Sous-echantillonnage systematique (n <= count) ou repetition du jeu avec
   decalage temporel d'une periode (n > count). */
static Dataset resize_dataset(const Dataset *src, size_t n, int64_t window_ms) {
    Dataset out = *src;
    out.records = malloc(n * sizeof(PacketRecord));
    if (!out.records) { fprintf(stderr, "Memoire insuffisante (taille %zu)\n", n); exit(1); }
    out.count = out.capacity = n;

    int64_t tmin = src->records[0].timestamp_ms, tmax = tmin;
    for (size_t i = 1; i < src->count; i++) {
        if (src->records[i].timestamp_ms < tmin) tmin = src->records[i].timestamp_ms;
        if (src->records[i].timestamp_ms > tmax) tmax = src->records[i].timestamp_ms;
    }
    int64_t offset = ((tmax - tmin) / window_ms + 1) * window_ms;

    for (size_t i = 0; i < n; i++) {
        if (n <= src->count) {
            out.records[i] = src->records[(size_t)((unsigned long long)i * src->count / n)];
        } else {
            size_t k = i / src->count, j = i % src->count;
            out.records[i] = src->records[j];
            out.records[i].timestamp_ms += (int64_t)k * offset;
        }
    }
    return out;
}

static int parse_list(const char *s, unsigned long long *v, int max) {
    char buf[256];
    strncpy(buf, s, sizeof buf - 1);
    buf[sizeof buf - 1] = '\0';
    int n = 0;
    for (char *t = strtok(buf, ","); t && n < max; t = strtok(NULL, ","))
        v[n++] = strtoull(t, NULL, 10);
    return n;
}

static int record_run(FILE *f, size_t n, const char *mode, int threads, int rep,
                      const RunResult *r, const Ref *ref) {
    int eq = stats_checksum(r->s) == ref->stats
          && alerts_checksum(&r->al) == ref->alerts
          && r->al.n == ref->n_alerts;
    double tot = r->t_analysis + r->t_detect;
    fprintf(f, "%zu,%s,%d,%d,%.6f,%.6f,%.6f,%.0f,%d\n",
            n, mode, threads, rep, r->t_analysis, r->t_detect, tot, n / tot, eq);
    if (!eq) fprintf(stderr, "ATTENTION : resultats differents (taille %zu, %s, %d threads)\n",
                     n, mode, threads);
    return eq;
}

static int run_benchmark(const Dataset *full, int window_s, unsigned scan_thr,
                         double spike_factor, const unsigned long long *sizes, int ns,
                         const unsigned long long *tl, int nt, int reps,
                         const char *out_path) {
    FILE *f = fopen(out_path, "w");
    if (!f) { perror(out_path); return 1; }
    fprintf(f, "size,mode,threads,rep,analysis_s,detection_s,total_s,throughput_flux_s,equivalent\n");
    int bad = 0;

    for (int si = 0; si < ns; si++) {
        size_t n = (size_t)sizes[si];
        Dataset ds = resize_dataset(full, n, (int64_t)window_s * 1000);
        Params p = make_params(&ds, window_s, scan_thr, spike_factor);
        fprintf(stderr, "[benchmark] taille %zu\n", n);

        RunResult r;
        run_once(&ds, &p, 0, 1, &r);                 /* echauffement, non enregistre */
        free_run(&r);

        Ref ref = {0, 0, 0};
        for (int rep = 0; rep < reps; rep++) {
            run_once(&ds, &p, 0, 1, &r);
            if (rep == 0) {
                ref.stats = stats_checksum(r.s);
                ref.alerts = alerts_checksum(&r.al);
                ref.n_alerts = r.al.n;
            }
            bad += !record_run(f, n, "sequential", 1, rep, &r, &ref);
            free_run(&r);
        }
        for (int ti = 0; ti < nt; ti++) {
            int threads = (int)tl[ti];
            fprintf(stderr, "  OpenMP %d threads\n", threads);
            for (int rep = 0; rep < reps; rep++) {
                run_once(&ds, &p, 1, threads, &r);
                bad += !record_run(f, n, "openmp", threads, rep, &r, &ref);
                free_run(&r);
            }
        }
        fflush(f);
        dataset_free(&ds);
    }
    fclose(f);
    fprintf(stderr, "[benchmark] termine : %s (%d execution(s) non equivalente(s))\n",
            out_path, bad);
    return bad ? 2 : 0;
}

/* ---------- programme principal ---------- */

int main(int argc, char **argv) {
    int window_s = 60, top_n = 10, nf = 0, reps = 5;
    int threads = omp_get_max_threads();
    unsigned scan_thr = 20;
    double spike_factor = 3.0;
    int ignore_rev = 0;
    const char *mode = "sequential";
    // const char *alerts_path = "results/alerts.csv";
    const char *alerts_path = NULL;
    const char *out_dir = NULL;
    char default_alerts[1100];
    const char *bench_out = "results/benchmark.csv";
    const char *sizes_arg = "100000,500000,1000000,5000000";
    const char *threads_arg = "1,2,4,8,12";
    const char *files[256];

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--window") && i + 1 < argc) window_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--top") && i + 1 < argc) top_n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--scan-threshold") && i + 1 < argc) scan_thr = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--spike-factor") && i + 1 < argc) spike_factor = atof(argv[++i]);
        else if (!strcmp(argv[i], "--alerts") && i + 1 < argc) alerts_path = argv[++i];
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sizes") && i + 1 < argc) sizes_arg = argv[++i];
        else if (!strcmp(argv[i], "--thread-list") && i + 1 < argc) threads_arg = argv[++i];
        else if (!strcmp(argv[i], "--reps") && i + 1 < argc) reps = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--bench-out") && i + 1 < argc) bench_out = argv[++i];
        else if (!strcmp(argv[i], "--ignore-reverse")) ignore_rev = 1;
        else if (!strcmp(argv[i], "--output") && i + 1 < argc) out_dir = argv[++i];
        else if (nf < 256) files[nf++] = argv[i];
    }

    int do_seq = 0, do_par = 0, do_bench = 0;
    if      (!strcmp(mode, "sequential")) do_seq = 1;
    else if (!strcmp(mode, "parallel"))   do_par = 1;
    else if (!strcmp(mode, "compare"))    do_seq = do_par = 1;
    else if (!strcmp(mode, "benchmark"))  do_bench = 1;
    else { fprintf(stderr, "Mode inconnu : %s\n", mode); return 1; }

    if (nf == 0 || window_s <= 0 || scan_thr == 0 || spike_factor <= 0 ||
        threads < 1 || reps < 1) {
        fprintf(stderr,
            "Usage: %s [--mode sequential|parallel|compare|benchmark] [--threads N]\n"
            "          [--window S] [--top N] [--scan-threshold N] [--spike-factor X]\n"
            "          [--alerts f.csv] [--sizes a,b,c] [--thread-list a,b,c]\n"
            "          [--reps N] [--bench-out f.csv] fichier1.csv [fichier2.csv ...]\n", argv[0]);
        return 1;
    }

    if (!alerts_path) {
        snprintf(default_alerts, sizeof default_alerts, "%s/alerts.csv",
                 out_dir ? out_dir : "results");
        alerts_path = default_alerts;
    }

    /* Ordonnancement : static par defaut, modifiable via OMP_SCHEDULE */
    if (!getenv("OMP_SCHEDULE")) omp_set_schedule(omp_sched_static, 0);
    detect_set_ignore_reverse(ignore_rev);

    Dataset ds;
    dataset_init(&ds);
    double t0 = now_s();
    for (int i = 0; i < nf; i++)
        if (load_csv(files[i], &ds) != 0) return 1;
    double t_load = now_s() - t0;

    if (ds.count == 0) { fprintf(stderr, "Aucun enregistrement valide.\n"); return 1; }

    if (do_bench) {
        unsigned long long sizes[MAX_LIST], tl[MAX_LIST];
        int ns = parse_list(sizes_arg, sizes, MAX_LIST);
        int nt = parse_list(threads_arg, tl, MAX_LIST);
        for (int i = 0; i < ns; i++) if (sizes[i] == 0) { fprintf(stderr, "Taille invalide\n"); return 1; }
        for (int i = 0; i < nt; i++) if (tl[i] == 0)    { fprintf(stderr, "Nombre de threads invalide\n"); return 1; }
        int ret = run_benchmark(&ds, window_s, scan_thr, spike_factor, sizes, ns, tl, nt,
                                reps, bench_out);
        dataset_free(&ds);
        return ret;
    }

    Params p = make_params(&ds, window_s, scan_thr, spike_factor);

    RunResult seq = {0}, par = {0};
    if (do_seq) run_once(&ds, &p, 0, 1, &seq);
    if (do_par) run_once(&ds, &p, 1, threads, &par);

    const RunResult *ref = do_seq ? &seq : &par;

    printf("Lignes lues: %zu | valides: %zu | invalides: %zu | vides: %zu\n",
           ds.lines_read, ds.count, ds.invalid, ds.blank);
    print_report(ref->s, &ds, top_n);
    print_alert_summary(&ref->al, top_n);
    evaluate_port_scans(&ds, &ref->al, p.scan_label);
    if (out_dir && export_results(out_dir, ref->s, &ds, top_n) == 0)
        printf("\nStatistiques exportees dans %s/\n", out_dir);
    if (alerts_write_csv(alerts_path, &ref->al) == 0)
        printf("Alertes exportees dans %s\n", alerts_path);

    printf("\n===== PERFORMANCE =====\n");
    printf("Parametres         : fenetre=%d s, seuil scan=%u ports, facteur pic=%.1f\n",
           window_s, scan_thr, spike_factor);
    printf("Filtre sens retour : %s\n", ignore_rev ? "oui" : "non");       
    printf("Machine            : %d processeurs logiques\n", omp_get_num_procs());
    printf("Chargement         : %.3f s (hors mesure)\n", t_load);
    if (do_seq) print_run("Sequentiel", &seq, ds.count);
    if (do_par) {
        char name[96];
        snprintf(name, sizeof name, "OpenMP (%d threads, ordonnancement %s)", threads, sched_name());
        print_run(name, &par, ds.count);
    }

    int ret = 0;
    if (do_seq && do_par) {
        int eq_stats  = stats_checksum(seq.s) == stats_checksum(par.s);
        int eq_alerts = alerts_checksum(&seq.al) == alerts_checksum(&par.al)
                        && seq.al.n == par.al.n;
        double tot_s = seq.t_analysis + seq.t_detect;
        double tot_p = par.t_analysis + par.t_detect;

        printf("\n===== COMPARAISON SEQUENTIEL / OPENMP (%d threads) =====\n", threads);
        printf("Speedup analyse    : %.2f   (efficacite %.1f %%)\n",
               seq.t_analysis / par.t_analysis, 100.0 * seq.t_analysis / par.t_analysis / threads);
        printf("Speedup detection  : %.2f   (efficacite %.1f %%)\n",
               seq.t_detect / par.t_detect, 100.0 * seq.t_detect / par.t_detect / threads);
        printf("Speedup total      : %.2f   (efficacite %.1f %%)\n",
               tot_s / tot_p, 100.0 * tot_s / tot_p / threads);
        printf("Equivalence stats  : %s\n", eq_stats ? "OUI" : "NON  <-- ERREUR");
        printf("Equivalence alertes: %s\n", eq_alerts ? "OUI" : "NON  <-- ERREUR");
        if (!eq_stats || !eq_alerts) ret = 2;
    }

    if (do_seq) free_run(&seq);
    if (do_par) free_run(&par);
    dataset_free(&ds);
    return ret;
}
