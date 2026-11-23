import os
import sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

d = sys.argv[1] if len(sys.argv) > 1 else "results/final"
fig_dir = "results/figures"
os.makedirs(fig_dir, exist_ok=True)

def save(name):
    plt.tight_layout()
    plt.savefig(os.path.join(fig_dir, name), dpi=150)
    plt.close()

ts = pd.read_csv(f"{d}/timeseries.csv", parse_dates=["window_start"])
alerts = pd.read_csv(f"{d}/alerts.csv", parse_dates=["window_start"])
proto = pd.read_csv(f"{d}/protocols.csv")
src = pd.read_csv(f"{d}/top_src_ips.csv")
dst = pd.read_csv(f"{d}/top_dst_ips.csv")
ports = pd.read_csv(f"{d}/top_dst_ports.csv")
summary = pd.read_csv(f"{d}/summary.csv")
print(summary.to_string(index=False))

# 1. Trafic dans le temps, un panneau par jour (les nuits sont vides)
days = sorted(ts["window_start"].dt.date.unique())
fig, axes = plt.subplots(1, len(days), figsize=(3.2 * len(days), 3.8), sharey=True, squeeze=False)
for ax, day in zip(axes[0], days):
    t = ts[ts["window_start"].dt.date == day]
    ax.plot(t["window_start"], t["flows"], lw=0.8)
    sp = alerts[(alerts["type"] == "traffic_spike_flows") & (alerts["window_start"].dt.date == day)]
    ax.scatter(sp["window_start"], sp["value"], color="red", s=14, zorder=3)
    ax.set_title(str(day), fontsize=9)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.tick_params(axis="x", labelsize=7, rotation=45)
axes[0][0].set_ylabel("Flux par fenetre (points rouges = pics)")
save("trafic_temps.png")

# 2. Protocoles
plt.figure(figsize=(5, 3.5))
plt.bar(proto["protocol"], proto["percent"])
plt.ylabel("% des flux")
plt.title("Repartition des protocoles")
save("protocoles.png")

# 3. Top IP et ports
def barh(df, labels, title, fname):
    plt.figure(figsize=(7, 4.5))
    plt.barh(labels[::-1], df["flows"][::-1])
    plt.xlabel("Flux")
    plt.title(title)
    save(fname)

barh(src, src["ip"].astype(str), "Top IP sources", "top_src.png")
barh(dst, dst["ip"].astype(str), "Top IP destinations", "top_dst.png")
barh(ports, ports["port"].astype(str), "Top ports destination", "top_ports.png")

# 4. Alertes de scan : avec / sans flux PortScan dans le groupe
scans = alerts[alerts["type"] == "port_scan"].copy()
if len(scans):
    scans["pair"] = scans["src_ip"] + " -> " + scans["dst_ip"]
    g = scans.groupby("pair").agg(total=("pair", "size"),
                                  avec_label=("portscan_labeled", lambda x: int((x > 0).sum())))
    g["sans_label"] = g["total"] - g["avec_label"]
    g = g.sort_values("total", ascending=False).head(10)
    plt.figure(figsize=(8, 4.5))
    plt.barh(g.index[::-1], g["avec_label"][::-1], label="contient des flux PortScan")
    plt.barh(g.index[::-1], g["sans_label"][::-1], left=g["avec_label"][::-1], label="aucun flux PortScan")
    plt.xlabel("Alertes de scan")
    plt.legend()
    plt.title("Alertes de scan par couple source -> destination")
    save("alertes_scan.png")

print("Alertes par type :")
print(alerts["type"].value_counts().to_string())
print("Figures dans", fig_dir)