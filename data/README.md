# Projet 06 : Analyse parallele du trafic reseau (C + OpenMP)

Analyse hors ligne de flux reseau (CIC-IDS2017) : statistiques, detection de scans de ports
et de pics de trafic, comparaison sequentiel / OpenMP.

## Prerequis
Ubuntu (WSL2 possible), `gcc` avec OpenMP, `make`, Python 3 avec pandas et matplotlib.

## Compilation
    make

## Utilisation
    ./network_analyzer --mode compare --threads 8 --scan-threshold 50 --ignore-reverse \
        --output results/final data/raw/*.csv

Options : `--mode sequential|parallel|compare|benchmark`, `--threads N`, `--window S`,
`--scan-threshold N`, `--spike-factor X`, `--ignore-reverse`, `--top N`, `--output DIR`,
`--alerts FICHIER`. Benchmark : `--sizes`, `--thread-list`, `--reps`, `--bench-out`.
Ordonnancement OpenMP : variable `OMP_SCHEDULE` (static par defaut).

## Benchmark et figures
    ./network_analyzer --mode benchmark --scan-threshold 50 --ignore-reverse \
        --sizes 500000,1000000,5000000 --thread-list 1,2,4,6,8,12 --reps 10 \
        --bench-out results/benchmark.csv data/raw/*.csv
    python3 dashboard/analyze_benchmark.py
    python3 dashboard/make_dashboard.py results/final

## Environnement de test
AMD Ryzen 5 5600H (6 coeurs, 12 threads), 11 Go de RAM, WSL2 Ubuntu 24.04,
GCC 13.3.0, options `-O2 -fopenmp`.

## Structure
`src/` sources C, `include/` en-tetes, `data/` jeu de donnees (non versionne),
`results/` sorties, `dashboard/` scripts Python, `docs/` rapport.
