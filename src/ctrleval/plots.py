"""Figures (matplotlib, Agg backend)."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

COL = {"literal": "#d1495b", "gate": "#edae49", "predicate": "#00798c", "best_response": "#30323d",
       "per-session": "#d1495b", "memory (last 3)": "#edae49", "memory (full)": "#00798c"}
LEVELS = ["L0 literal", "L1 constants", "L2 composed", "L3 aliased"]


def _style(ax):
    ax.grid(alpha=.25)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)


def stage1(res: dict, out: Path) -> None:
    sv = res["safety_vs_budget"]
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    for name, rows in sv.items():
        x = [r["budget"] * 100 for r in rows]
        y = [r["safety"] for r in rows]
        ax.plot(x, y, "o-" if name == "best_response" else "o--", color=COL[name], lw=2.4 if name == "best_response" else 1.5,
                label=("red best response" if name == "best_response" else f"{name} backdoor"))
        if name != "best_response":
            ax.fill_between(x, [r["lo"] for r in rows], [r["hi"] for r in rows], color=COL[name], alpha=.12)
    ax.set_xscale("log"); ax.set_ylim(0, 1.02)
    ax.set_xlabel("audit budget (% of submissions audited)"); ax.set_ylabel(f"safety (n={res['config']['n_deploy']} tasks)")
    ax.set_title("Stage 1: safety vs audit budget"); ax.legend(frameon=False, fontsize=8); _style(ax)
    fig.tight_layout(); fig.savefig(out / "stage1_safety_vs_budget.png", dpi=160); plt.close(fig)

    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    for (name, pts), c in zip(res["pareto"].items(), ["#30323d", "#edae49", "#d1495b"]):
        ax.plot([p["usefulness_norm"] for p in pts], [p["safety"] for p in pts], "o-", color=c, label=name)
        for p in pts[::2]:
            ax.annotate(f"{p['budget']*100:g}%", (p["usefulness_norm"], p["safety"]), fontsize=7, xytext=(3, 3), textcoords="offset points")
    ax.set_xlabel("usefulness (0 = trusted model only, 1 = untrusted only)"); ax.set_ylabel("safety vs red best response")
    ax.set_title("Stage 1: safety vs usefulness (labels = audit budget)"); ax.legend(frameon=False, fontsize=8); _style(ax)
    fig.tight_layout(); fig.savefig(out / "stage1_safety_vs_usefulness.png", dpi=160); plt.close(fig)

    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    sig = sorted(res["noise_sweep"], key=float)
    for st in ("literal", "gate", "predicate"):
        ax.plot([float(s) for s in sig], [res["noise_sweep"][s][st] for s in sig], "o-", color=COL[st], label=st)
    ax.set_xlabel("monitor noise (sigma)"); ax.set_ylabel("safety at 2% audit budget"); ax.set_ylim(0, 1.02)
    ax.set_title("Stage 1: a weaker monitor loses safety"); ax.legend(frameon=False, fontsize=8); _style(ax)
    fig.tight_layout(); fig.savefig(out / "stage1_monitor_noise.png", dpi=160); plt.close(fig)


def stage2(res: dict, out: Path, budget: str = "0.05") -> None:
    cells = res["cells"]

    def get(n, lvl, gap, mon):
        return next(c for c in cells if c["n_sessions"] == n and c["level"] == lvl and c["gap"] == gap and c["monitor"] == mon)

    fig, axes = plt.subplots(1, 4, figsize=(14, 3.6), sharey=True)
    for lvl, ax in enumerate(axes):
        for mon in ("per-session", "memory (last 3)", "memory (full)"):
            c = get(4, lvl, 0, mon)["catch"]
            xs = sorted(c, key=float)
            y = [c[x][0] for x in xs]
            ax.plot([float(x) * 100 for x in xs], y, "o-", color=COL[mon], label=mon)
            ax.fill_between([float(x) * 100 for x in xs], [c[x][1] for x in xs], [c[x][2] for x in xs], color=COL[mon], alpha=.12)
        ax.set_xscale("log"); ax.set_title(LEVELS[lvl], fontsize=10); ax.set_xlabel("audit budget (% of sessions)"); _style(ax)
    axes[0].set_ylabel("plan caught (4 sessions, no gap)"); axes[0].legend(frameon=False, fontsize=8)
    fig.suptitle("Stage 2: catch rate vs audit budget", y=1.02); fig.tight_layout()
    fig.savefig(out / "stage2_catch_vs_budget.png", dpi=160, bbox_inches="tight"); plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), sharey=True)
    for ax, mon in zip(axes, ("per-session", "memory (full)")):
        m = np.array([[get(n, l, 0, mon)["catch"][budget][0] for l in range(4)] for n in range(1, 6)])
        im = ax.imshow(m, vmin=0, vmax=1, cmap="viridis", aspect="auto")
        ax.set_xticks(range(4), LEVELS, fontsize=8); ax.set_yticks(range(5), [f"{n} session{'s' if n > 1 else ''}" for n in range(1, 6)])
        for i in range(5):
            for j in range(4):
                ax.text(j, i, f"{m[i, j]:.2f}", ha="center", va="center", color="w" if m[i, j] < .6 else "k", fontsize=9)
        ax.set_title(mon)
    fig.colorbar(im, ax=axes, shrink=.8, label=f"catch rate @ {float(budget)*100:g}% budget")
    fig.suptitle("Stage 2: how many sessions the plan is split over x how its pieces are linked")
    fig.savefig(out / "stage2_heatmap.png", dpi=160, bbox_inches="tight"); plt.close(fig)

    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    for gap, c in zip((0, 1, 2, 4), ["#00798c", "#30323d", "#edae49", "#d1495b"]):
        rows = [r for r in res["window_ablation"] if r["gap"] == gap]
        xs = [r["window"] if r["window"] is not None else 12 for r in rows]
        ax.plot(xs, [r["catch_5pct"] for r in rows], "o-", color=c, label=f"{gap} benign sessions between steps")
    ax.set_xticks([1, 2, 3, 5, 8, 12], ["1", "2", "3", "5", "8", "full"])
    ax.set_xlabel("sessions of memory the monitor can read"); ax.set_ylabel("catch rate @ 5% budget")
    ax.set_title("Stage 2: memory window needed (4-session plan, L1)"); ax.legend(frameon=False, fontsize=8); _style(ax)
    fig.tight_layout(); fig.savefig(out / "stage2_memory_window.png", dpi=160); plt.close(fig)
