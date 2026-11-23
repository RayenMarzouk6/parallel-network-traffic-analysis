import os
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

df = pd.read_csv("results/benchmark.csv")
os.makedirs("results/figures", exist_ok=True)

g = df.groupby(["size", "mode", "threads"]).agg(
    analysis_mean=("analysis_s", "mean"),
    detection_mean=("detection_s", "mean"),
    total_mean=("total_s", "mean"),
    total_std=("total_s", "std"),
    total_median=("total_s", "median"),
    throughput_mean=("throughput_flux_s", "mean"),
    all_equivalent=("equivalent", "min"),
).reset_index()

seq = g[g["mode"] == "sequential"].set_index("size")
for col in ["analysis", "detection", "total"]:
    g[f"speedup_{col}"] = g.apply(
        lambda r: seq.loc[r["size"], f"{col}_mean"] / r[f"{col}_mean"], axis=1)
g["efficiency_total_pct"] = 100 * g["speedup_total"] / g["threads"]
g.to_csv("results/benchmark_summary.csv", index=False)
print(g.round(4).to_string(index=False))

par = g[g["mode"] == "openmp"]
sizes = sorted(par["size"].unique())

def plot(ycol, ylabel, fname, ideal=False, logy=False):
    plt.figure(figsize=(7, 4.5))
    for s in sizes:
        d = par[par["size"] == s].sort_values("threads")
        plt.plot(d["threads"], d[ycol], marker="o", label=f"{s:,} flux")
    if ideal:
        t = sorted(par["threads"].unique())
        plt.plot(t, t, "k--", label="ideal")
    plt.xlabel("Threads OpenMP")
    plt.ylabel(ylabel)
    if logy:
        plt.yscale("log")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"results/figures/{fname}", dpi=150)
    plt.close()

plot("total_mean", "Temps total (s)", "temps_total.png", logy=True)
plot("speedup_total", "Speedup (total)", "speedup.png", ideal=True)
plot("efficiency_total_pct", "Efficacite (%)", "efficacite.png")
plot("throughput_mean", "Debit (flux/s)", "debit.png")
print("Figures dans results/figures/")
