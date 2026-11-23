# Parallel Network Traffic Analysis (C + OpenMP)

Offline network traffic analysis and anomaly detection on the **CIC-IDS2017** dataset, implemented in C with a
sequential baseline and an **OpenMP** parallel version, plus a reproducible benchmark.

> Academic project (Project 06) for the module *Atelier de programmation sur machines à mémoire distribuée
> (Grilles de calcul)*, class CCDAD 2, ISET Sousse.
> Author: Rayen [YOUR LAST NAME].

## Table of contents

1. [Overview](#overview)
2. [Features](#features)
3. [Repository structure](#repository-structure)
4. [Requirements](#requirements)
5. [Dataset](#dataset)
6. [Build](#build)
7. [Usage](#usage)
8. [Command-line options](#command-line-options)
9. [Output files](#output-files)
10. [How it works](#how-it-works)
11. [Results](#results)
12. [Reproducing the benchmark](#reproducing-the-benchmark)
13. [Limitations](#limitations)
14. [Report](#report)
15. [Citation and data license](#citation-and-data-license)

## Overview

The program loads network **flow** records (not individual packets), validates them, computes traffic statistics
(IP addresses, ports, protocols, volumes, time series), and detects two kinds of suspicious behaviour:

- **Possible port scans**: one source contacts many distinct destination ports of the same host within a time window.
- **Traffic spikes**: a time window whose flow count or byte volume greatly exceeds the recent baseline.

The same analysis is implemented twice, sequentially and with OpenMP threads. The program checks automatically that
both versions produce **identical results** (order-independent checksums), then reports execution time, throughput,
speedup and efficiency.

Alerts are indicators for investigation, not proof of an attack. This tool is meant for defensive, academic analysis
of an authorised dataset.

## Features

- CSV loader with validation (IPv4 syntax, port range, numeric fields, timestamps) and counters for valid, invalid
  and blank rows.
- Statistics: totals, unique IPs and ports, per-protocol counts, top source/destination IPs (by flows and bytes),
  top destination ports, per-window time series, label distribution.
- Sequential and OpenMP analysis sharing the same per-record function, so both versions do the same work.
- Port-scan and traffic-spike detection with configurable thresholds and window length.
- Evaluation of the port-scan detector against the dataset labels (TP, FP, FN, precision, recall, F1).
- Benchmark mode over several dataset sizes and thread counts, with repeated runs and a correctness check on every run.
- CSV export of statistics and alerts, and Python scripts that generate the figures.

## Repository structure

```
project-06-network-traffic/
├── src/
│   ├── main.c                  # options, modes (sequential, parallel, compare, benchmark)
│   ├── csv_reader.c            # CSV parsing, validation, normalisation
│   ├── ipmap.c                 # open-addressing hash table (IP -> counters)
│   ├── statistics.c            # statistics, merge, checksum, report printing
│   ├── sequential_analyzer.c   # sequential analysis loop
│   ├── openmp_analyzer.c       # OpenMP analysis and port-scan detection
│   ├── detection.c             # port scans, traffic spikes, evaluation, alert export
│   └── export.c                # CSV export of statistics
├── include/
│   ├── packet_record.h         # record structure and dataset container
│   ├── analyzer.h              # statistics API
│   └── detection.h             # detection API
├── dashboard/
│   ├── analyze_benchmark.py    # benchmark summary and performance figures
│   ├── make_dashboard.py       # traffic, protocol, top-N and alert figures
│   └── review_spikes.py        # compares spike alerts with documented attack times
├── data/
│   ├── README_dataset.md       # dataset description and preprocessing choices
│   └── raw/                    # CSV files (NOT in the repository, see Dataset)
├── results/                    # benchmark CSVs, exported statistics, figures
├── docs/                       # technical report (LaTeX source)
├── Makefile
├── requirements.txt            # Python dependencies for the dashboard scripts
└── README.md
```

## Requirements

- Linux or WSL2 (developed on Ubuntu 24.04 under WSL2)
- `gcc` with OpenMP support (developed with GCC 13.3.0), `make`
- Python 3 with `pandas` and `matplotlib` (only for the figures)

```bash
sudo apt update
sudo apt install build-essential gcc make python3 python3-pandas python3-matplotlib
```

## Dataset

The CIC-IDS2017 data is **not included** in this repository (about 1.2 GB).

1. Download `GeneratedLabelledFlows.zip` from the official page:
   <https://www.unb.ca/cic/datasets/ids-2017.html>
2. Extract it and copy the 8 CSV files of the `TrafficLabelling` folder into `data/raw/`:

```
data/raw/
├── Monday-WorkingHours.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
├── Wednesday-workingHours.pcap_ISCX.csv
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
├── Friday-WorkingHours-Morning.pcap_ISCX.csv
├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
└── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

Use `GeneratedLabelledFlows.zip`, not `MachineLearningCSV.zip`: only the former contains IP addresses and timestamps.
Keep the files on the Linux filesystem (not under `/mnt/c`) for fast loading and stable timings.

Measured on the 8 files: 3,119,345 lines read, **2,830,743 valid flows**, 288,602 blank lines (only commas),
0 invalid lines. See [`data/README_dataset.md`](data/README_dataset.md) for the column mapping and the preprocessing
decisions (date format, 12-hour times, number formats, units).

## Build

```bash
make
```

This compiles `src/*.c` into the `network_analyzer` executable (`gcc -O2 -Wall -Wextra -fopenmp -Iinclude`).
The executable is generated and is not versioned. `make clean` removes it.

## Usage

Run the sequential analysis:

```bash
./network_analyzer --mode sequential --scan-threshold 50 --ignore-reverse data/raw/*.csv
```

Compare sequential and OpenMP (8 threads), check equivalence, and export results:

```bash
./network_analyzer --mode compare --threads 8 --scan-threshold 50 --ignore-reverse \
    --top 20 --output results/final data/raw/*.csv
```

The program prints the statistics, the alerts, the evaluation, the timings, and (in `compare` mode) the speedup,
the efficiency and `Equivalence stats : OUI / Equivalence alertes : OUI`. It exits with code 2 if the two versions
disagree. Console messages are in French.

Run a single file for a quick test:

```bash
./network_analyzer data/raw/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
```

## Command-line options

| Option | Description | Default |
|---|---|---|
| `--mode` | `sequential`, `parallel`, `compare` or `benchmark` | `sequential` |
| `--threads N` | Number of OpenMP threads | all logical processors |
| `--window S` | Time-window length in seconds | `60` |
| `--scan-threshold N` | Minimum distinct destination ports for a scan alert | `20` |
| `--ignore-reverse` | Ignore flows with source port < 1024 and destination port >= 1024 (server replies) | off |
| `--spike-factor X` | A window is a spike if its value exceeds X times the baseline mean | `3.0` |
| `--top N` | Size of the top-N rankings | `10` |
| `--output DIR` | Directory for exported statistics (the directory must have an existing parent) | none |
| `--alerts FILE` | Path of the alerts CSV | `results/alerts.csv` (or `DIR/alerts.csv`) |
| `--sizes a,b,c` | Benchmark dataset sizes | `100000,500000,1000000,5000000` |
| `--thread-list a,b,c` | Benchmark thread counts | `1,2,4,8,12` |
| `--reps N` | Benchmark repetitions per configuration | `5` |
| `--bench-out FILE` | Benchmark output CSV | `results/benchmark.csv` |

Environment variables: `OMP_SCHEDULE` (default `static`; try `dynamic,10000` or `guided`), `OMP_PLACES` and
`OMP_PROC_BIND` (thread placement), and `DEBUG_INVALID=1` (prints the reason and examples of rejected CSV lines).

## Output files

With `--output results/final`:

| File | Content |
|---|---|
| `summary.csv` | records read/valid/invalid/blank, flows, packets, bytes, unique IPs and ports |
| `protocols.csv` | flows, percentage and bytes per protocol |
| `labels.csv` | flows per ground-truth label |
| `timeseries.csv` | flows and bytes per non-empty time window |
| `top_src_ips.csv`, `top_dst_ips.csv`, `top_dst_ports.csv` | top-N rankings |
| `alerts.csv` | alerts: type, window, source, destination, value, threshold, score, severity, group size, labelled scan flows |

Benchmark mode writes `size,mode,threads,rep,analysis_s,detection_s,total_s,throughput_flux_s,equivalent`.

## How it works

**Pipeline:** load and validate CSV → normalised 40-byte records → analysis (sequential or OpenMP) → detection →
export and figures.

**Parallel analysis.** Records are split among threads with `omp for`. Each thread accumulates into its own local
statistics (arrays for ports, protocols and labels, a hash table for IPs, arrays for time windows), then merges them
into the global result inside a critical section, once per thread. No shared counter is updated concurrently.

**Parallel port-scan detection.** Flows are grouped by (source, destination, window). Each group is assigned to exactly
one thread by hashing the triplet, so no lock is needed. Each thread sorts its flows, counts distinct ports per group,
and produces local alerts that are concatenated and sorted into a canonical order.

**Port-scan rule.** Alert when a source contacts at least `--scan-threshold` distinct destination ports (TCP/UDP) of
the same destination within one window. Optional `--ignore-reverse` removes server-to-client replies, which appear as
separate flows in the data and look like a host contacting thousands of ports.

**Traffic-spike rule.** For each non-empty window, compare the flow count (or byte count) with `factor` times the
mean of the previous 10 **non-empty** windows. At least 3 baseline windows and a minimum volume (100 flows or 1 MiB)
are required. Spike detection is sequential in both modes (about 6,200 windows).

**Correctness check.** Statistics and alerts are summarised by order-independent checksums. The sequential and
parallel results must match, in `compare` mode and for every run of the benchmark.

## Results

Environment: AMD Ryzen 5 5600H (6 cores / 12 threads), 11 GiB RAM, Ubuntu 24.04 on WSL2, GCC 13.3.0, `-O2 -fopenmp`,
`OMP_PLACES=cores OMP_PROC_BIND=close` (requested; not guaranteed to be applied under WSL2).
Analysis and detection only (CSV loading excluded). Means of 10 runs, 5,000,000 flows.

| Threads | Time (s) | Speedup | Efficiency | Throughput (flows/s) |
|---:|---:|---:|---:|---:|
| Sequential | 0.8559 | 1.00 | n/a | 5.85 M |
| 1 | 0.8763 | 0.98 | 98 % | 5.71 M |
| 2 | 0.5118 | 1.67 | 84 % | 9.78 M |
| 4 | 0.2939 | 2.91 | 73 % | 17.05 M |
| 6 | 0.2528 | 3.39 | 56 % | 19.80 M |
| 8 | 0.2397 | **3.57** | 45 % | 20.88 M |
| 12 | 0.2674 | 3.20 | 27 % | 18.75 M |

Speedup at 8 threads for the other sizes: 3.44 (500,000 flows) and 3.00 (1,000,000 flows).
All 210 benchmark runs matched the sequential reference.

Observations (explanations are hypotheses, not measured):

- 8 threads performed best for every size and 12 threads were slower. The CPU has 6 physical cores, so the extra
  logical threads probably share cores.
- Efficiency decreases as threads are added. Possible causes: each thread scans the whole array to select its
  detection partition, merging per-thread structures, memory bandwidth.
- **End-to-end gain is only about 1.10**, because CSV loading (about 3 s for the full dataset) is not parallelised.
- Static scheduling was fastest for the analysis phase (0.0312 s vs 0.0375 s dynamic and 0.0378 s guided, 8 threads).
- Timings vary between measurement series (the 12-thread speedup at 5 M flows ranged from 2.70 to 3.94 across series).

Detection (full dataset, threshold 50, `--ignore-reverse`): 344 alerts (62 port scans, 88 flow spikes,
194 byte spikes). Flow-level evaluation of port scans against the `PortScan` label:
TP = 158,549, FP = 65,286, FN = 381, **precision 0.708, recall 0.998, F1 0.828**.
Without `--ignore-reverse`, precision was 0.569 at the same threshold (recall unchanged).

## Reproducing the benchmark

```bash
OMP_PLACES=cores OMP_PROC_BIND=close \
./network_analyzer --mode benchmark --scan-threshold 50 --ignore-reverse \
    --sizes 500000,1000000,5000000 --thread-list 1,2,4,6,8,12 --reps 10 \
    --bench-out results/benchmark.csv data/raw/*.csv

python3 dashboard/analyze_benchmark.py          # summary CSV + performance figures
python3 dashboard/make_dashboard.py results/final   # traffic, protocol, top-N, alert figures
python3 dashboard/review_spikes.py results/alerts.csv 2   # spike alerts vs documented attack times
```

Close other applications during the benchmark. Sizes below the full dataset are systematic samples; the
5,000,000-flow input repeats the full dataset (about 1.77 times) with a time offset, so it is replicated data, not
independent traffic.

## Limitations

- The data are **flows**, not packets; all rates are in flows per second.
- Ground truth is imperfect: some flows are recorded in both directions, and some real behaviour is unlabelled.
  For example, 192.168.10.8 performs an internal port scan documented on the dataset page (Thursday afternoon),
  but its flows are labelled `BENIGN`, so those alerts count as false positives and the measured precision is
  probably underestimated.
- The threshold was chosen and evaluated on the same data, so the metrics are optimistic.
- `--ignore-reverse` is a heuristic: a scanner using a low source port would be ignored.
- Spike detection has no window-level labels, so no precision is reported. Its baseline crosses day boundaries, which
  can create alerts in the first minutes of a day.
- Timestamps have no AM/PM indicator; hours below 8 are interpreted as afternoon (the data contains no traffic
  before 8 a.m.). Only IPv4 is supported.
- Benchmarks were run on one machine under WSL2, and the effect of thread placement is not guaranteed.

## Report

The detailed technical report (in French) is in [`docs/`](docs/) (`rapport.tex`; compile with `pdflatex`).

## Citation and data license

This repository contains code only. The dataset is distributed by the Canadian Institute for Cybersecurity
(University of New Brunswick); according to its page, it is publicly available for researchers, who must cite:

> I. Sharafaldin, A. Habibi Lashkari and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and
> Intrusion Traffic Characterization", 4th International Conference on Information Systems Security and Privacy
> (ICISSP), January 2018.

Use only datasets you are authorised to analyse. This tool does not capture, scan or block any network traffic.

<!-- Add a LICENSE file for the code if you want to specify reuse terms. -->