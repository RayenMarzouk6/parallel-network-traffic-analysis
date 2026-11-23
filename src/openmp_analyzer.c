#include <stdlib.h>
#include <omp.h>
#include "analyzer.h"
#include "detection.h"

/* Statistiques : compteurs locaux par thread, puis fusion. */
void analyze_parallel(const Dataset *ds, Stats *s, int threads) {
    #pragma omp parallel num_threads(threads)
    {
        Stats *local = stats_create(s->t0_ms, s->window_ms, s->n_windows);

        #pragma omp for schedule(runtime) nowait
        for (long long i = 0; i < (long long)ds->count; i++)
            stats_add_record(local, &ds->records[i]);

        #pragma omp critical(stats_merge_section)
        stats_merge(s, local);

        stats_destroy(local);
    }
}

/* Detection de scans : chaque thread traite sa partition de groupes (src,dst,fenetre). */
void detect_port_scans_parallel(const Dataset *ds, int64_t t0_ms, int64_t window_ms,
                                unsigned threshold, int scan_label, int threads,
                                AlertList *out) {
    #pragma omp parallel num_threads(threads)
    {
        AlertList local;
        alerts_init(&local);

        detect_port_scans(ds, t0_ms, window_ms, threshold, scan_label,
                          omp_get_thread_num(), omp_get_num_threads(), &local);

        #pragma omp critical(alerts_merge_section)
        alerts_append(out, &local);

        alerts_free(&local);
    }
}
