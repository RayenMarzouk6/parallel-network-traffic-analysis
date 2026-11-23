#include "analyzer.h"

void analyze_sequential(const Dataset *ds, Stats *s) {
    for (size_t i = 0; i < ds->count; i++)
        stats_add_record(s, &ds->records[i]);
}
