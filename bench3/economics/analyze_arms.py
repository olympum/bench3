#!/usr/bin/env python3
"""How much of the user's subscription Nexus routing saves (ADR 0015 arms, bench3 imported role tasks).

For each arm: success, escalation rate, the user's subscription use and the LunaRoute lane time it moves onto
Mithran. Subscription use is token counts at list price (API-equivalent USD): the whole run for the opus arm,
the escalation children for nexus-escalate. Results per role family and call-weighted by role (the operator's
census). Only valid records count; a task missing from an arm is reported, not imputed.

usage: analyze_arms.py [--effort default] [--rep 101]
"""
import argparse, json, glob
from collections import defaultdict
from pathlib import Path

ECON = Path(__file__).resolve().parent
ARMS = ["opus-login", "nexus-escalate-gateway", "nexus-gateway", "glm53-flash-gateway", "ds41-gateway"]
ROLE = {"polyglot": "coder", "code-contests": "coder", "swe-verified": "coder", "swe-locate": "explorer",
        "swe-review": "reviewer", "primevul": "deep-reviewer", "iac-eval": "coder-iac"}
WEIGHTS = {"coder": 31.4, "reviewer": 24.7, "explorer": 12.0, "coder-iac": 10.2, "deep-reviewer": 7.4}


def load(effort, rep):
    recs = {}
    for f in ECON.glob("agentic_results/*_%s_rep%d.json" % (effort, rep)):
        r = json.loads(f.read_text())
        if r.get("arm") and r["route_id"] in ARMS and r["task"].startswith("imported/") and "/smoke/" not in r["task"]:
            recs[(r["route_id"], r["task"])] = r
    return recs


def subscription_usd(r):
    if r["arm"] == "opus":
        return r["costs"].get("api_equivalent_usd", 0.0)
    return r["costs"].get("escalation_api_equivalent_usd", 0.0)


def subscription_tokens(r):
    if r["arm"] == "opus":
        u = r["usage"]
        return u["total_tokens"]
    u = r.get("escalation_usage") or {}
    return u.get("input", 0) + u.get("cached", 0) + u.get("output", 0)


def lane_seconds(r):
    if r["arm"] == "opus":
        return 0.0
    child = sum((e.get("duration_ms") or 0) for e in r.get("escalations") or []) / 1000
    return max(0.0, r["elapsed_seconds"] - child)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--effort", default="default")
    ap.add_argument("--rep", type=int, default=101)
    a = ap.parse_args()
    recs = load(a.effort, a.rep)
    tasks = sorted({t for (_, t) in recs})
    valid = {k: r for k, r in recs.items() if r["valid"]}
    print("records %d, valid %d, tasks %d" % (len(recs), len(valid), len(tasks)))
    for arm in ARMS:
        missing = [t for t in tasks if (arm, t) not in valid]
        if missing:
            print("  %s: %d tasks without a valid record" % (arm, len(missing)))

    # Compare arms only on tasks every arm completed validly, so totals are like for like.
    common = [t for t in tasks if all((arm, t) in valid for arm in ARMS)]
    per_role = defaultdict(int)
    for t in common:
        per_role[ROLE[t.split("/")[1]]] += 1
    wsum = sum(WEIGHTS[r] for r in per_role)
    weight = {t: WEIGHTS[ROLE[t.split("/")[1]]] / wsum / per_role[ROLE[t.split("/")[1]]] for t in common}

    def row(arm, subset, w=None):
        n = len(subset)
        if not n:
            return None
        ww = (lambda t: w[t]) if w else (lambda t: 1 / n)
        agg = defaultdict(float)
        for t in subset:
            r = valid[(arm, t)]
            k = ww(t)
            agg["success"] += k * bool(r["grade"].get("passed"))
            agg["escalated"] += k * bool(r.get("escalations"))
            agg["sub_usd"] += k * subscription_usd(r)
            agg["sub_tok"] += k * subscription_tokens(r)
            agg["lane_s"] += k * lane_seconds(r)
            agg["wall_s"] += k * r["elapsed_seconds"]
        return agg

    def show(title, subset, w=None):
        print("\n%s (%d tasks)" % (title, len(subset)))
        print("%-24s %8s %10s %16s %16s %12s %10s" % ("arm", "success", "escalated", "sub USD/100 tasks",
                                                    "sub tokens/task", "lane-min/task", "wall-min"))
        base = row("opus-login", subset, w)
        for arm in ARMS:
            g = row(arm, subset, w)
            if g is None:
                continue
            print("%-24s %7.1f%% %9.1f%% %16.2f %16.0f %12.1f %10.1f" % (
                arm, 100 * g["success"], 100 * g["escalated"], 100 * g["sub_usd"], g["sub_tok"], g["lane_s"] / 60, g["wall_s"] / 60))
        esc = row("nexus-escalate-gateway", subset, w)
        if base and esc and base["sub_usd"]:
            print("subscription saved by nexus-escalate vs opus: %.1f%% of API-equivalent USD, %.1f%% of tokens; success %+.1f pts"
                  % (100 * (1 - esc["sub_usd"] / base["sub_usd"]), 100 * (1 - esc["sub_tok"] / base["sub_tok"]),
                     100 * (esc["success"] - base["success"])))

    show("All roles, unweighted", common)
    show("All roles, call-weighted by role", common, weight)
    for role in sorted(per_role):
        show("Role: %s" % role, [t for t in common if ROLE[t.split("/")[1]] == role])


if __name__ == "__main__":
    main()
