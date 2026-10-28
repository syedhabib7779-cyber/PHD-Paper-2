import sys, pandas as pd, numpy as np, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
T = sys.argv[1]; OUT = sys.argv[2]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
D = pd.read_csv(T + "/R7_dense_grid.csv")
ARMS = [("random_forest", "raw30", "#c0392b", "RF / raw30"), ("xgboost", "raw30", "#e67e22", "XGBoost / raw30"),
        ("mlp", "raw30", "#7f8c8d", "MLP / raw30"), ("random_forest", "invariant19", "#2471a3", "RF / invariant19")]
DOM = [("src", "CICIDS2017 (source)"), ("tgt", "CSE-CIC-IDS2018 (target)")]
fig, axs = plt.subplots(2, 2, figsize=(10, 7), sharey="row")
for r, (xl, tag) in enumerate([((0.45, 2.2), "full range"), ((0.85, 1.15), "zoom")]):
    for c, (dom, dname) in enumerate(DOM):
        ax = axs[r, c]
        for m, f, col, lab in ARMS:
            g = D[(D.model == m) & (D.features == f) & (D.domain == dom) & D.k.between(*xl)]
            if m in ("random_forest", "xgboost") and f == "raw30":
                for s, gs in g.groupby("seed"):
                    gs = gs.sort_values("k"); ax.plot(gs.k, gs.preserved, color=col, lw=0.8, alpha=0.45, drawstyle="steps-mid")
            mu = g.groupby("k").preserved.mean()
            ax.plot(mu.index, mu.values, color=col, lw=2.2, drawstyle="steps-mid")
        ax.axvline(1.0, color="#999", ls=":", lw=1)
        if r == 1:
            for kk in (0.97, 1.03): ax.axvline(kk, color="#bbb", ls="--", lw=0.8)
        ax.set_xscale("log"); ax.set_xlim(*xl)
        ticks = [0.5, 0.75, 1.0, 1.5, 2.0] if r == 0 else [0.85, 0.9, 0.95, 1.0, 1.05, 1.1, 1.15]
        ax.set_xticks(ticks); ax.set_xticklabels([str(t) for t in ticks]); ax.minorticks_off()
        ax.set_title("({}) {}, {}".format("abcd"[2 * r + c], dname, tag), fontsize=10, loc="left")
        ax.set_xlabel("re-timing factor k (log scale)")
        if c == 0: ax.set_ylabel("preservation $P_f(k)$")
        ax.set_ylim(0.65, 1.02)
h = [Line2D([], [], color=col, lw=2.2, label=lab + " (mean of seeds 1–5)") for _, _, col, lab in ARMS] + \
    [Line2D([], [], color="#555", lw=0.8, alpha=0.6, label="individual seeds 1–5 (raw tree ensembles)")]
fig.legend(handles=h, loc="lower center", ncol=3, frameon=False, fontsize=9)
fig.tight_layout(rect=(0, 0.07, 1, 1)); fig.savefig(OUT + "/fig5_dense_v5.png", dpi=300); plt.close(fig)

B = pd.read_csv(T + "/R11_benign_retiming.csv")
B = B[(B.threshold == "src_cal_0.001") & (B.aug == "none")]
ARMS2 = [("random_forest", "raw30", "#c0392b", "RF / raw30"), ("xgboost", "raw30", "#e67e22", "XGBoost / raw30"),
         ("mlp", "raw30", "#7f8c8d", "MLP / raw30"), ("random_forest", "invariant19", "#2471a3", "RF / invariant19"),
         ("xgboost", "invariant19", "#5dade2", "XGBoost / invariant19"), ("mlp", "inv18", "#1e8449", "MLP / invariant18")]
fig, axs = plt.subplots(1, 2, figsize=(10, 3.9))
for ax, (dom, dname), lab in zip(axs, DOM, "ab"):
    for m, f, col, l in ARMS2:
        g = B[(B.model == m) & (B.features == f) & (B.domain == dom)]
        st = g.groupby("k").fpr_k.agg(["mean", "min", "max"])
        ax.plot(st.index, st["mean"], color=col, lw=2, marker="o", ms=3, label=l)
        ax.fill_between(st.index, st["min"], st["max"], color=col, alpha=0.12)
    ax.axvline(1.0, color="#999", ls=":", lw=1); ax.axhline(0.001, color="#555", ls="--", lw=0.8)
    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xticks([0.5, 0.75, 1, 1.5, 2]); ax.set_xticklabels(["0.5", "0.75", "1", "1.5", "2"]); ax.minorticks_off()
    ax.set_title("({}) {}".format(lab, dname), fontsize=10, loc="left"); ax.set_xlabel("re-timing factor k applied to benign flows (log scale)")
    if lab == "a": ax.set_ylabel("benign FPR at frozen threshold (log)")
h, l = axs[0].get_legend_handles_labels()
fig.legend(h, l, loc="lower center", ncol=3, frameon=False, fontsize=9)
fig.tight_layout(rect=(0, 0.13, 1, 1)); fig.savefig(OUT + "/fig6_benign_v5.png", dpi=300)
print("ok")
