"""ctrleval stage1 | stage2 | all  -> JSON + PNGs under --out (default results/)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import plots


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="ctrleval", description=__doc__)
    ap.add_argument("stage", choices=["stage1", "stage2", "all"])
    ap.add_argument("--out", default="results")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--plans", type=int, default=60, help="stage 2: attack plans per cell")
    ap.add_argument("--benign", type=int, default=250, help="stage 2: benign projects for calibration")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(exist_ok=True, parents=True)
    if a.stage in ("stage1", "all"):
        from .control import Config, run
        from .pool import build_pool
        res = run(build_pool(a.seed), Config(seed=a.seed))
        (out / "stage1.json").write_text(json.dumps(res, indent=1))
        plots.stage1(res, out)
        print("stage1 ->", out)
    if a.stage in ("stage2", "all"):
        from .session import eval as ev
        res = ev.run(plans=a.plans, n_benign=a.benign, seed=a.seed)
        (out / "stage2.json").write_text(json.dumps(res, indent=1))
        plots.stage2(res, out)
        print("stage2 ->", out)


if __name__ == "__main__":
    main()
