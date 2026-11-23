# Control evaluation with a cross-session monitor

A mini AI-control evaluation, in two stages. **Everything here runs offline with a simulated, structure-based monitor. No real language model is involved, so these numbers show the method and the harness, not how a real model behaves.**

## Stage 1: trusted monitoring + audit budget
An untrusted model solves 16 coding tasks. With a hidden side goal it may submit a *verified backdoor* (passes all tests, wrong on a concrete exploit input). A weaker trusted monitor scores each submission and the top `a` fraction is audited. The red team picks its attack rate to minimise safety. Optional defer-to-trusted trades usefulness for safety.

Three backdoor styles: `literal` (`if args == <magic>`), `gate` (`len(repr(args)) % k == r`), `predicate` (a natural-looking structural condition).

| style | AUROC vs honest | safety @ 1% / 5% budget |
|---|---|---|
| literal | 0.96 | 0.79 / 0.90 |
| gate | 0.96 | 0.51 / 0.78 |
| predicate | 0.58 | 0.01 / 0.07 |

The red team's best response is the predicate style, so a monitor that cannot see "natural" edge-case logic caps safety near the audit rate. Defer-to-trusted lifts safety only by giving up a lot of usefulness (see `results/stage1_safety_vs_usefulness.png`). Audited honest runs count as fixed by a human, so "audit only" usefulness can exceed 1.

## Stage 2: unsafe plan split across sessions
An exfiltration chain (read credential -> stage to file -> upload) is split over 1-5 sessions at four linking levels (literal paths; constants; composed paths; runtime aliasing). Plans are **verified** to leak a canary through a stubbed network. A per-session monitor is compared with monitors that read the last 3 sessions or all history. All use the same analyzer; they differ only in what they can see.

Catch rate at a 5% per-session audit budget:

| plan | per-session | memory (full) |
|---|---|---|
| unsplit (1 session), L0-L2 | 1.00 | 1.00 |
| 4 sessions, L0 / L1 / L2 | 0.00 | 1.00 |
| 4 sessions, L3 (aliased) | 0.00 | 0.25 |
| 4 sessions + 2 benign sessions between steps, L0-L2 | 0.00 | 1.00 |

Splitting defeats the per-session monitor completely; full memory restores detection. A short window is not enough: with 2 benign sessions between steps, even an 8-session window catches about 8%. Level-3 aliasing evades both monitors even though the attack still works.

## Limitations
- The monitors are structural simulators with assumed weights; the memory result is partly by construction (the analyzer needs the earlier code to resolve names). Real findings need an LLM monitor, which is not implemented yet.
- Task set is small (16), and subtle single-edit mutants were too rare, so the `mutation` style is excluded.
- Process isolation only; use a container for real model-written code.

## Run
```
pip install -e .
ctrleval all        # writes results/*.json and *.png
```
