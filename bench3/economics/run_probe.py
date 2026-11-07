#!/usr/bin/env python3
"""Probe imported tasks on a few routes to see whether a source spreads cheap and frontier routes apart.

Runs every task under tasks/imported/ (or --family) through run_agentic.run_one on the given routes and
repetitions, two at a time. Token-billed spend is summed from the saved records before each token-billed
run, and the probe stops starting such runs once --max-usd is reached.

usage: run_probe.py --route glm53-flash-lunaroute:2 --route claude-opus55-openrouter:1 --max-usd 25
       [--family polyglot] [--limit 1200] [--jobs 2]
       run_probe.py --summary
"""
from __future__ import annotations

import argparse
import json
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import BENCH, ECON, load_config
from run_agentic import run_one

RESULTS = ECON / "agentic_results"
REP_BASE = 100  # probe repetitions are numbered from 101 so they never collide with campaign records
LOCK = threading.Lock()


def imported_tasks(family: str | None) -> list[str]:
    root = BENCH / "tasks" / "imported"

    def kept(task: Path) -> bool:  # tasks whose grader failed the two-way check are never run
        meta = task / ".import.json"
        return meta.exists() and json.loads(meta.read_text()).get("validation", {}).get("kept", False)

    return sorted(str(p.parent.relative_to(BENCH / "tasks")) for p in root.glob("*/*/PROMPT.txt")
                  if (family is None or p.parent.parent.name == family) and kept(p.parent))


def spent_usd() -> float:
    total = 0.0
    for f in RESULTS.glob("*.json"):
        r = json.loads(f.read_text())
        if r.get("repetition", 0) > REP_BASE and r["costs"]["billing"] == "token":
            total += r["costs"]["cash_cost_usd"]
    return total


def summary() -> None:
    rows = defaultdict(lambda: {"runs": 0, "valid": 0, "passed": 0, "usd": 0.0, "lane_s": 0.0, "api_eq": 0.0, "seconds": []})
    per_task = defaultdict(dict)
    for f in sorted(RESULTS.glob("*.json")):
        r = json.loads(f.read_text())
        if r.get("repetition", 0) <= REP_BASE or not r["task"].startswith("imported/"):
            continue
        family = r["task"].split("/")[1]
        route_label = r["route_id"] + (" [claude-code]" if r.get("harness") == "claude-code" else "")
        key = (family, route_label)
        row = rows[key]
        row["runs"] += 1
        row["valid"] += bool(r["valid"])
        if not r["valid"]:
            continue  # an invalid run measured nothing; it is counted, not scored
        row["passed"] += bool(r["grade"].get("passed"))
        row["seconds"].append(r["elapsed_seconds"])
        if r["costs"]["billing"] == "subscription":
            row["lane_s"] += r["elapsed_seconds"]
        elif r["costs"]["billing"] == "user-subscription":
            row["api_eq"] += r["costs"].get("api_equivalent_usd", 0.0)
        if r["costs"].get("escalation_api_equivalent_usd"):
            row["api_eq"] += r["costs"]["escalation_api_equivalent_usd"]
        else:
            row["usd"] += r["costs"]["cash_cost_usd"]
        cell = per_task[r["task"]].setdefault(route_label, [0, 0])
        cell[0] += bool(r["grade"].get("passed")); cell[1] += 1
    for (family, route), row in sorted(rows.items()):
        s = sorted(row["seconds"])
        print("%-14s %-42s runs %2d valid %2d passed %2d  usd %.3f  api-eq %.3f  lane-s %.0f  median-s %.0f"
              % (family, route, row["runs"], row["valid"], row["passed"], row["usd"], row["api_eq"], row["lane_s"],
                 s[len(s) // 2] if s else 0))
    print()
    for task, cells in sorted(per_task.items()):
        label = lambda route_id: (route_id.replace("claude-", "").replace("-openrouter", "").replace("-lunaroute", "")
                                  .replace("-direct [claude-code]", "/cc-apikey").replace("-claudecode-sub", "/cc-sub").replace("-codex-sub", "/codex-sub").replace(" ", ""))
        print("%-48s %s" % (task, "  ".join("%s %d/%d" % (label(k), v[0], v[1]) for k, v in sorted(cells.items()))))
    print("\ntoken-billed spend in probe records: USD %.3f" % spent_usd())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--route", action="append", default=[], help="route_id:repetitions")
    ap.add_argument("--family")
    ap.add_argument("--max-usd", type=float, default=0.0)
    ap.add_argument("--limit", type=int, default=1200)
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--task", action="append", default=[], help="limit to these imported tasks")
    a = ap.parse_args()
    if a.summary:
        summary()
        return 0
    config = load_config()
    jobs = []
    for spec in a.route:
        route_id, reps = spec.split(":")
        for task in [t for t in imported_tasks(a.family) if not a.task or t in a.task]:
            for rep in range(1, int(reps) + 1):
                jobs.append((route_id, task, REP_BASE + rep))

    def one(job):
        route_id, task, rep = job
        token_billed = config["routes"][route_id]["billing"] == "token"  # lane plans and user subscriptions cost Mithran nothing per run
        with LOCK:
            if token_billed and spent_usd() >= a.max_usd:
                print("ceiling reached, skipping %s %s rep %d" % job, flush=True)
                return
        effort = config["routes"][route_id].get("effort") or "high"
        stem = "%s_%s_%s_rep%d" % (route_id, task.replace("/", "-"), effort, rep)
        prior = RESULTS / (stem + ".json")
        if prior.exists() and json.loads(prior.read_text())["valid"]:
            return
        try:
            run_one(config, route_id, "high", task, rep, a.limit, True)  # an invalid earlier record is replaced
        except Exception as exc:  # a provider or harness failure is recorded and the probe moves on
            print("FAILED %s %s rep %d: %s" % (route_id, task, rep, exc), flush=True)

    # A route's runs share one DSH home, so each route runs its jobs in order; routes run side by side.
    by_route = defaultdict(list)
    for job in jobs:
        by_route[job[0]].append(job)
    with ThreadPoolExecutor(a.jobs) as pool:
        list(pool.map(lambda route_jobs: [one(j) for j in route_jobs], by_route.values()))
    summary()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
