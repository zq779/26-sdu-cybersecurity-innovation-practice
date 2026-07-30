#!/usr/bin/env python3
from pathlib import Path
import csv
import matplotlib.pyplot as plt

root = Path(__file__).resolve().parents[1]
csv_path = root / "report" / "benchmark.csv"
out_path = root / "report" / "benchmark.png"

rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
backends = []
for row in rows:
    if row["backend"] not in backends:
        backends.append(row["backend"])
modes = ["ECB", "CTR", "GCM", "XTS"]
values = {(r["backend"], r["mode"]): float(r["MiB_per_s"]) for r in rows}

x = range(len(backends))
width = 0.18
fig, ax = plt.subplots(figsize=(10, 5.5))
for idx, mode in enumerate(modes):
    positions = [v + (idx - 1.5) * width for v in x]
    ax.bar(positions, [values[(b, mode)] for b in backends], width, label=mode)
ax.set_yscale("log")
ax.set_ylabel("Throughput (MiB/s, log scale)")
ax.set_xlabel("AES backend")
ax.set_xticks(list(x), backends)
ax.set_title("AES software optimization benchmark")
ax.legend()
ax.grid(axis="y", which="both", linestyle="--", linewidth=0.5)
fig.tight_layout()
fig.savefig(out_path, dpi=180)
print(out_path)
