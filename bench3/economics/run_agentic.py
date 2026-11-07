#!/usr/bin/env python3
"""Run current model routes through the DSH agent harness."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from common import BENCH, ECON, calculate_cost, load_config, load_credentials

sys.path.append(str(BENCH / "bin"))
from lib.session import decompress, parse_session, wait_session  # noqa: E402


DSH_TEMPLATE_HOME = BENCH / ".dsh-home"
ISOLATED_DSH_HOME = Path(tempfile.gettempdir()) / "bench3-economics-dsh-home"
AEGIS_PAYLOAD_PATH = ECON / "aegis_method_payload.md"
SETTINGS_TEMPLATE = ECON / "dsh_settings.template.yaml"


def load_aegis_payload() -> tuple[str, str]:
    payload = AEGIS_PAYLOAD_PATH.read_text()
    return payload, hashlib.sha256(payload.encode()).hexdigest()


def workspace_key(path: Path) -> str:
    return "--" + str(path.resolve()).lstrip("/").replace("/", "-") + "--"


def hide_test_assets(work: Path) -> None:
    for name in ("PROMPT.txt", "hidden_test.py", "_hidden_test.py"):
        path = work / name
        if path.exists():
            path.unlink()
    for name in ("reference", "__pycache__"):
        path = work / name
        if path.exists() and path.is_dir():
            shutil.rmtree(path)


def make_sandbox_profile(root: Path, work: Path) -> Path:
    """Allow normal execution, but deny all reads and writes to the source repo."""
    profile = root / "agent.sb"
    repo_root = BENCH.parent
    profile.write_text(
        '(version 1)\n'
        '(allow default)\n'
        '(deny file-read* file-write* (subpath %s))\n' % json.dumps(str(repo_root))
    )
    visible_file = next(path for path in work.rglob("*") if path.is_file())
    probe = subprocess.run(
        [
            "/usr/bin/sandbox-exec", "-f", str(profile), "/bin/sh", "-c",
            'cat "$1" >/dev/null && ! cat "$2" >/dev/null 2>&1',
            "probe", str(visible_file), str(BENCH / "tasks" / "coding" / "c1_deadlock" / "hidden_test.py"),
        ],
        capture_output=True, text=True,
    )
    if probe.returncode != 0:
        raise RuntimeError("file sandbox probe failed")
    return profile


def isolated_dsh_home(
    provider: str, model: str, effort: str, aegis_payload: str | None = None,
) -> tuple[Path, bool]:
    """Return (home, needs_prime). Every run gets a fresh home: DSH 0.2 applies imported settings for one
    boot after the import and a reused home fell back to its default route, so each home is primed once."""
    tag = "%s-%s-%s-%s" % (provider, model, effort, "aegis" if aegis_payload else "base")
    ISOLATED_DSH_HOME.mkdir(parents=True, exist_ok=True)
    home = Path(tempfile.mkdtemp(prefix=re.sub(r"[^A-Za-z0-9._-]", "_", tag) + "-", dir=ISOLATED_DSH_HOME))
    if not (home / "profiles").exists():
        shutil.copytree(
            DSH_TEMPLATE_HOME / "profiles", home / "profiles",
            ignore=shutil.ignore_patterns("node_modules"),
        )
    # DSH 0.2 imports settings.yaml into its store and renames it, so the template lives in the repo.
    with SETTINGS_TEMPLATE.open() as handle:
        settings = yaml.safe_load(handle) or {}
    if provider == "openai":
        providers = settings.setdefault("llm-pi-ai", {}).setdefault("providers", {})
        openai = providers.setdefault("openai", {})
        openai.setdefault("apiKeyEnv", "OPENAI_API_KEY")
        openai.setdefault("api", "openai-responses")
        models = openai.setdefault("models", [])
        if not any(item.get("id") == model for item in models):
            models.append({
                "id": model,
                "reasoningEfforts": {
                    "off": "none", "minimal": "minimal", "low": "low",
                    "medium": "medium", "high": "high", "xhigh": "xhigh",
                    "max": "max",
                },
            })
    settings["agent-default-model"] = {
        "provider": provider,
        "model": model,
        "reasoningEffort": effort,
    }
    # DSH 0.2 imports settings.yaml into storages/ during a run and applies it from the next boot on,
    # so a changed home is primed once with a trivial task before it is measured.
    text = yaml.safe_dump(settings, sort_keys=False)
    applied = home / "settings.applied.yaml"
    needs_prime = not applied.exists() or applied.read_text() != text
    if needs_prime:
        if (home / "storages").exists():
            shutil.rmtree(home / "storages")
        (home / "settings.yaml").write_text(text)
        applied.write_text(text)
    persona = "You are a coding agent powered by the {{model}} model. Your working directory is {{cwd}}."
    if aegis_payload:
        persona += "\n\n" + aegis_payload
    patch = [{"id": "system-prompt", "config": {"persona": persona}}]
    patch_path = home / "profiles" / "headless" / "cordis.patch.yml"
    patch_path.write_text(yaml.safe_dump(patch, sort_keys=False))
    return home, needs_prime


def forbidden_repo_access(session_path: Path) -> list[str]:
    """Return tool-call records that directly reference the benchmark source."""
    found = []
    source_root = str(BENCH)
    for line in decompress(session_path).splitlines():
        try:
            event = json.loads(line)
        except Exception:
            continue
        if event.get("type") != "tool/call":
            continue
        data = json.dumps(event.get("data", {}), separators=(",", ":"))
        if source_root in data:
            found.append(data[:1000])
    return found


def credential_exposure(paths: list[Path], creds: dict[str, str]) -> list[str]:
    """Names of files under paths that contain any stored credential value. Values are never returned."""
    secrets = [v.encode() for v in creds.values() if len(v) >= 12]
    hits = []
    for root in paths:
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for path in files:
            data = path.read_bytes()
            if path.suffix == ".zstd":
                data = decompress(path).encode()
            if any(s in data for s in secrets):
                hits.append(path.name)
    return hits


def response_ids(session_path: Path) -> list[str]:
    ids = []
    for line in decompress(session_path).splitlines():
        try:
            event = json.loads(line)
        except Exception:
            continue
        source = event.get("data", {}).get("message", {}).get("source", {})
        replay = source.get("replayState") or {}
        response_id = replay.get("responseId") or (replay.get("response") or {}).get("responseId")
        if response_id and response_id not in ids:
            ids.append(str(response_id))
    return ids


def openrouter_generation_cost(ids: list[str], key: str) -> tuple[float | None, list[str]]:
    if not key or not ids:
        return None, []
    costs = []
    providers = []
    for response_id in ids:
        url = "https://openrouter.ai/api/v1/generation?id=" + response_id
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + key})
        row = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    row = json.load(response).get("data", {})
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404 and attempt < 3:
                    time.sleep(3)
                    continue
                break
        if not row or row.get("total_cost") is None:
            return None, providers
        costs.append(float(row["total_cost"]))
        if row.get("provider_name"):
            providers.append(str(row["provider_name"]))
    return sum(costs), sorted(set(providers))


def grade(task_dir: Path, work: Path) -> dict[str, Any]:
    hidden = task_dir / "hidden_test.py"
    if not hidden.exists():
        return {"kind": "ungraded", "passed": None}
    shutil.copy2(hidden, work / "_hidden_test.py")
    started = time.time()
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "_hidden_test", "-v"],
        cwd=work, capture_output=True, text=True, timeout=300,
    )
    text = result.stdout + "\n" + result.stderr
    return {
        "kind": "hidden-tests",
        "passed": result.returncode == 0,
        "seconds": time.time() - started,
        "tests_failed": len(re.findall(r"^(?:FAIL|ERROR):", text, re.M)),
        "tail": text[-2000:],
    }


def run_one(
    config: dict[str, Any], route_id: str, effort: str, task: str, rep: int,
    limit: int, force: bool, aegis_injected: bool = False,
    parent_record_path: str | None = None,
) -> dict[str, Any]:
    route = config["routes"][route_id]
    if route.get("arm"):
        return run_one_arm(config, route_id, effort, task, rep, limit, force)
    task_dir = BENCH / "tasks" / task
    prompt_path = task_dir / "PROMPT.txt"
    if not prompt_path.exists():
        raise ValueError("agentic task required: %s" % task)
    suffix = "_aegis" if aegis_injected else ""
    stem = "%s_%s_%s_rep%d%s" % (
        route_id, task.replace("/", "-"), effort, rep, suffix,
    )
    record_path = ECON / "agentic_results" / (stem + ".json")
    if record_path.exists() and not force:
        print("skip existing: %s" % record_path)
        return json.loads(record_path.read_text())

    started = datetime.now(timezone.utc)
    temp_root = Path(tempfile.mkdtemp(prefix="bench3-economics-"))
    work = temp_root / "work"
    shutil.copytree(task_dir, work)
    prompt = prompt_path.read_text()
    hide_test_assets(work)
    sandbox_profile = make_sandbox_profile(temp_root, work)

    model = route.get("agent_model", route["model"])
    aegis_payload = None
    aegis_payload_sha256 = None
    if aegis_injected:
        aegis_payload, aegis_payload_sha256 = load_aegis_payload()
    dsh_home, needs_prime = isolated_dsh_home(route["provider"], model, effort, aegis_payload)
    creds = load_credentials()
    # The agent's shell inherits this environment, so it gets only the key its own route needs.
    env = {k: v for k, v in os.environ.items() if k not in creds}
    env[route["credential"]] = creds.get(route["credential"], "")
    if route["provider"] != "deepseek-official":
        # DSH 0.2 boots its native DeepSeek adapter even when the route is elsewhere and refuses an empty key.
        env.setdefault("DEEPSEEK_API_KEY", "unused-by-this-route")
    env["DSH_HOME"] = str(dsh_home)
    if needs_prime:
        prime = temp_root / "prime"
        prime.mkdir()
        subprocess.run(["dsh", "--profile", "headless", "Reply with exactly: OK"],
                       cwd=prime, env=env, capture_output=True, text=True, timeout=300)
    log_path = ECON / "agentic_runs" / (stem + ".log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timed_out = False
    begin = time.time()
    try:
        result = subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(sandbox_profile), "dsh", "--profile", "headless", prompt],
            cwd=work, env=env,
            capture_output=True, text=True, timeout=limit,
        )
        exit_code = result.returncode
        log_path.write_text(result.stdout + "\n--- STDERR ---\n" + result.stderr)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        log_path.write_text(stdout + "\n--- STDERR ---\n" + stderr)
    elapsed = time.time() - begin

    session_path = wait_session(workspace_key(work), dsh_home, started.timestamp(), timeout=120)
    if not session_path:
        raise RuntimeError("no DSH session after agent run")
    leak_evidence = forbidden_repo_access(session_path)
    secret_hits = credential_exposure([session_path, log_path, work], creds)
    if secret_hits:
        # Nothing that holds a key is kept; the run counts as invalid.
        log_path.write_text("redacted: a stored credential value appeared in this run's output\n")
        leak_evidence = leak_evidence + ["credential value in " + hit for hit in secret_hits]
    parsed = parse_session(session_path)
    served = sorted({(e["provider"], e["model"]) for e in parsed["events"] if e["type"] == "assistant"})
    if served != [(route["provider"], model)]:
        # A stale DSH store can keep an earlier route's model; such a run measures the wrong route.
        leak_evidence = leak_evidence + ["served by %s, not %s/%s" % (served, route["provider"], model)]
    raw_usage = parsed["usage"]
    usage = {
        "input_tokens": raw_usage["input"] + raw_usage["cached"],
        "cache_read_tokens": raw_usage["cached"],
        "cache_write_tokens": 0,
        "output_tokens": raw_usage["output"],
        "reasoning_tokens": raw_usage["reasoning"],
        "total_tokens": raw_usage["input"] + raw_usage["cached"] + raw_usage["output"],
        "calls": raw_usage["calls"],
    }

    ids = response_ids(session_path)
    provider_cost = None
    upstream_providers: list[str] = []
    cost_source = "capacity-allocation" if route["billing"] == "subscription" else "list-price"
    cost_route = dict(route)
    if route["provider"] == "openrouter":
        provider_cost, upstream_providers = openrouter_generation_cost(
            ids, creds.get("OPENROUTER_API_KEY", "")
        )
        if provider_cost is not None:
            cost_source = "provider-reported"
        elif route.get("agent_estimate_prices"):
            cost_route["prices"] = route["agent_estimate_prices"]
            cost_source = "advertised-floor-estimate"
        else:
            cost_source = "catalog-estimate"
    costs = calculate_cost(config, cost_route, usage, started, provider_cost=provider_cost)
    artifact_path = ECON / "agentic_artifacts" / (stem + "_" + str(int(started.timestamp())))
    result_grade = grade(task_dir, work)
    if not secret_hits:
        shutil.copytree(work, artifact_path)
    if leak_evidence:
        result_grade["passed"] = False
        result_grade["invalid_reason"] = "; ".join(leak_evidence) if not secret_hits else "credential value in run output"
    saved_session = ECON / "agentic_sessions" / stem / "session.jsonl.zstd"
    if secret_hits:
        session_path.unlink()
    else:
        saved_session.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(session_path, saved_session)
    record = {
        "schema_version": "bench3.economics.agentic.v1",
        "catalog_as_of": config["catalog_as_of"],
        "started_at_utc": started.isoformat(),
        "route_id": route_id,
        "route": {key: route[key] for key in (
            "model_family", "display", "vendor", "route", "provider", "billing"
        )},
        "model": model,
        "task": task,
        "effort": effort,
        "repetition": rep,
        "condition": "aegis_retry" if aegis_injected else "base",
        "parent_record_path": parent_record_path,
        "aegis": {
            "injected": aegis_injected,
            "payload_path": str(AEGIS_PAYLOAD_PATH) if aegis_injected else None,
            "payload_sha256": aegis_payload_sha256,
        },
        "elapsed_seconds": elapsed,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "sandbox_enforced": True,
        "valid": not leak_evidence,
        "leak_evidence": leak_evidence,
        "usage": usage,
        "costs": costs,
        "cost_source": cost_source,
        "upstream_providers": upstream_providers,
        "grade": result_grade,
        "record_path": str(record_path),
        "session_path": str(saved_session),
        "log_path": str(log_path),
        "artifact_path": str(artifact_path),
        "response_ids": ids,
    }
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(record, indent=1))
    print(
        "%s | %s | pass=%s | %.1fs | %d calls | %d tokens | cost=%s | %s"
        % (
            route_id, task, result_grade["passed"], elapsed, usage["calls"], usage["total_tokens"],
            "$%.6f" % (costs["capacity_allocated_cost_usd"] if costs["billing"] == "subscription" else costs["cash_cost_usd"]),
            cost_source,
        )
    )
    return record


GATEWAY_URL = os.environ.get("BENCH3_GATEWAY_URL", "http://127.0.0.1:18990")
GATEWAY_TOKEN = Path(os.environ.get("BENCH3_GATEWAY_TOKEN_FILE", str(Path.home() / "nexeval-bench3" / ".gw-token")))
GATEWAY_LOG = os.environ.get("BENCH3_GATEWAY_LOG", "")
AEGIS_BIN = os.environ.get("BENCH3_AEGIS_BIN", str(Path.home() / "nexeval-bench3" / "aegis-src" / "target" / "release" / "aegis"))
ESCALATE_TOOL = "mcp__aegis__escalate"


def arm_command(route: dict[str, Any], effort: str, prompt: str, root: Path) -> tuple[list[str], dict[str, str]]:
    """Claude Code as the user runs it under PLG V1 (ADR 0018), for one ADR 0015 arm.

    Every arm loads only project and local settings, so the user's own CLAUDE.md, hooks and plugins stay out,
    the same flags aegis escalate-mcp gives its child. Gateway arms point Claude Code at the gateway with every
    model slot on the route's model; the escalate arm adds the escalate MCP server and declares its tool to the
    gateway by header. The child that escalate-mcp starts runs on the user's own login: escalate-mcp strips the
    gateway settings, and no API key is set.
    """
    model = route["model"]
    env = {"DISABLE_TELEMETRY": "1", "ANTHROPIC_DEFAULT_HAIKU_MODEL": model, "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
           "ANTHROPIC_DEFAULT_OPUS_MODEL": model}
    cmd = ["claude", "-p", prompt, "--model", model, "--setting-sources", "project,local", "--strict-mcp-config",
           "--permission-mode", "bypassPermissions", "--output-format", "stream-json", "--verbose"]
    effort = route.get("effort") or effort
    if effort:
        cmd += ["--effort", effort]
    if route.get("gateway"):
        env.update({"ANTHROPIC_BASE_URL": GATEWAY_URL, "ANTHROPIC_API_KEY": GATEWAY_TOKEN.read_text().strip()})
    if route.get("escalate"):
        mcp = {"mcpServers": {"aegis": {"type": "stdio", "command": AEGIS_BIN, "args": ["escalate-mcp"], "alwaysLoad": True,
                                        "env": {"AEGIS_ESCALATE_MODEL": route["escalate_model"],
                                                "AEGIS_ESCALATE_PERMISSION_MODE": "bypassPermissions",
                                                "AEGIS_ESCALATE_MAX_SECONDS": os.environ.get("BENCH3_ESCALATE_MAX_SECONDS", "1800")}}}}
        (root / "escalate-mcp.json").write_text(json.dumps(mcp))
        cmd += ["--mcp-config", str(root / "escalate-mcp.json")]
        env["ANTHROPIC_CUSTOM_HEADERS"] = "x-aegis-escalate-tool: " + ESCALATE_TOOL
    return cmd, env


def parse_stream(stdout: str) -> dict[str, Any]:
    """Parent usage and models, escalate calls and their child results, from Claude Code's stream-json output."""
    out = {"usage": {"input": 0, "cached": 0, "cache_write": 0, "output": 0}, "turns": 0, "models": set(),
           "escalations": [], "result": {}}
    calls = {}
    for line in stdout.splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("type") == "assistant":
            msg = e.get("message") or {}
            out["models"].add(msg.get("model"))
            for block in msg.get("content") or []:
                if block.get("type") == "tool_use" and block.get("name") == ESCALATE_TOOL:
                    calls[block.get("id")] = block.get("input")
        elif e.get("type") == "user":
            for block in (e.get("message") or {}).get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") in calls:
                    text = block.get("content")
                    text = " ".join(x.get("text", "") for x in text if isinstance(x, dict)) if isinstance(text, list) else str(text)
                    structured = (e.get("tool_use_result") or {}) if isinstance(e.get("tool_use_result"), dict) else {}
                    try:
                        child = structured.get("structuredContent") or json.loads(text)
                    except (json.JSONDecodeError, TypeError):
                        child = {"raw": text[:2000]}
                    out["escalations"].append(child)
        elif e.get("type") == "result":
            out["result"] = e
            u = e.get("usage") or {}
            out["usage"] = {"input": u.get("input_tokens", 0), "cached": u.get("cache_read_input_tokens", 0),
                            "cache_write": u.get("cache_creation_input_tokens", 0), "output": u.get("output_tokens", 0)}
            out["turns"] = e.get("num_turns", 0)
            out["model_usage"] = e.get("modelUsage") or {}
    out["models"] = sorted(m for m in out["models"] if m)
    return out


def gateway_window(start: float, end: float) -> dict[str, Any]:
    """Upstream dispatches and usage the gateway logged in [start, end]: the route evidence for a gateway arm."""
    seen = {"dispatches": {}, "input": 0, "output": 0, "classifier_calls": 0}
    if not GATEWAY_LOG or not os.path.exists(GATEWAY_LOG):
        return seen
    for line in open(GATEWAY_LOG, errors="ignore"):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = e.get("timestamp")
        if not ts:
            continue
        t = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        if not start <= t <= end:
            continue
        if e.get("event") == "upstream_request_dispatched":
            key = "%s/%s" % (e.get("provider"), e.get("target"))
            seen["dispatches"][key] = seen["dispatches"].get(key, 0) + 1
        elif e.get("event") == "aegis_usage_observation":
            seen["input"] += e.get("input_tokens") or 0
            seen["output"] += e.get("output_tokens") or 0
        elif e.get("event") == "nexus_classifier_call":
            seen["classifier_calls"] += 1
    return seen


def price(usage: dict[str, int], prices: dict[str, float]) -> float:
    return (usage["input"] * prices["input"] + usage["cached"] * prices["cached_input"]
            + usage.get("cache_write", 0) * prices.get("cache_write", prices["input"]) + usage["output"] * prices["output"]) / 1e6


def run_one_arm(
    config: dict[str, Any], route_id: str, effort: str, task: str, rep: int, limit: int, force: bool,
) -> dict[str, Any]:
    """One ADR 0015 arm on one task: the same task, file sandbox, credential scan and grader as run_one."""
    route = config["routes"][route_id]
    task_dir = BENCH / "tasks" / task
    prompt = (task_dir / "PROMPT.txt").read_text()
    stem = "%s_%s_%s_rep%d" % (route_id, task.replace("/", "-"), route.get("effort") or effort, rep)
    record_path = ECON / "agentic_results" / (stem + ".json")
    if record_path.exists() and not force:
        print("skip existing: %s" % record_path)
        return json.loads(record_path.read_text())

    started = datetime.now(timezone.utc)
    temp_root = Path(tempfile.mkdtemp(prefix="bench3-economics-"))
    work = temp_root / "work"
    shutil.copytree(task_dir, work)
    hide_test_assets(work)
    sandbox_profile = make_sandbox_profile(temp_root, work)
    cmd, arm_env = arm_command(route, effort, prompt, temp_root)
    creds = load_credentials()
    env = {k: v for k, v in os.environ.items() if k not in creds and not k.startswith(("ANTHROPIC", "OPENAI", "CLAUDE_CODE"))}
    env.update(arm_env)
    log_path = ECON / "agentic_runs" / (stem + ".log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timed_out, stdout = False, ""
    begin = time.time()
    try:
        result = subprocess.run(["/usr/bin/sandbox-exec", "-f", str(sandbox_profile), *cmd], cwd=work, env=env,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=limit)
        exit_code, stdout = result.returncode, result.stdout
        log_path.write_text(result.stdout + "\n--- STDERR ---\n" + result.stderr)
    except subprocess.TimeoutExpired as exc:
        timed_out, exit_code = True, 124
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        log_path.write_text(stdout)
    end = time.time()
    elapsed = end - begin

    evidence = []
    secret_hits = credential_exposure([log_path, work], creds)
    if secret_hits:
        log_path.write_text("redacted: a stored credential value appeared in this run's output\n")
        evidence.append("credential value in " + ", ".join(secret_hits))
    parsed = parse_stream(stdout)
    gw = gateway_window(begin, end + 5) if route.get("gateway") else None
    children = parsed["escalations"]
    child_models = sorted({str(c.get("model")) for c in children if c.get("model")})
    # ADR 0015's routing evidence; a run without it is invalid, not a failure of the arm.
    if route["arm"] == "opus":
        if not parsed["models"] or any(not m.startswith(route["model"]) for m in parsed["models"]):
            evidence.append("parent served by %s, not only %s" % (parsed["models"], route["model"]))
    else:
        if not gw or not gw["dispatches"]:
            evidence.append("no gateway dispatch recorded for the run")
        elif any(not k.startswith("lunaroute/") for k in gw["dispatches"]):
            evidence.append("gateway dispatched outside LunaRoute: %s" % gw["dispatches"])
        if route["arm"] == "model" and any(k != route["model"] for k in gw["dispatches"]):
            evidence.append("gateway served %s, not %s" % (gw["dispatches"], route["model"]))
        if not route.get("escalate") and children:
            evidence.append("escalation in an arm without the escalate tool")
        if route.get("escalate") and any(m and not m.startswith(route["escalate_model"]) for m in child_models):
            evidence.append("child served by %s, not %s" % (child_models, route["escalate_model"]))
    child_usage = {"input": 0, "cached": 0, "cache_write": 0, "output": 0}
    for c in children:
        u = c.get("usage") or {}
        child_usage["input"] += u.get("input_tokens", 0)
        child_usage["cached"] += u.get("cache_read_input_tokens", 0)
        child_usage["cache_write"] += u.get("cache_creation_input_tokens", 0)
        child_usage["output"] += u.get("output_tokens", 0)
    raw = parsed["usage"]
    usage = {"input_tokens": raw["input"] + raw["cached"] + raw["cache_write"], "cache_read_tokens": raw["cached"],
             "cache_write_tokens": raw["cache_write"], "output_tokens": raw["output"], "reasoning_tokens": 0,
             "total_tokens": raw["input"] + raw["cached"] + raw["cache_write"] + raw["output"], "calls": parsed["turns"]}
    if route["arm"] == "opus":
        costs = {"billing": "user-subscription", "cash_cost_usd": 0.0, "api_equivalent_usd": price(raw, route["prices"])}
    else:
        costs = {"billing": "subscription", "cash_cost_usd": 0.0, "capacity_allocated_cost_usd": 0.0,
                 "escalation_api_equivalent_usd": price(child_usage, route["escalate_prices"]) if route.get("escalate") else 0.0}
    result_grade = grade(task_dir, work)
    if evidence:
        result_grade["passed"] = False
        result_grade["invalid_reason"] = "; ".join(evidence)
    artifact_path = ECON / "agentic_artifacts" / (stem + "_" + str(int(started.timestamp())))
    if not secret_hits:
        shutil.copytree(work, artifact_path)
    record = {
        "schema_version": "bench3.economics.agentic.v1", "arm": route["arm"], "harness": "claude-code",
        "harness_version": subprocess.run(["claude", "--version"], capture_output=True, text=True).stdout.strip(),
        "catalog_as_of": config["catalog_as_of"], "started_at_utc": started.isoformat(), "route_id": route_id,
        "route": {key: route[key] for key in ("model_family", "display", "vendor", "route", "provider", "billing")},
        "model": route["model"], "task": task, "effort": route.get("effort") or effort, "repetition": rep,
        "condition": "base", "elapsed_seconds": elapsed, "exit_code": exit_code, "timed_out": timed_out,
        "sandbox_enforced": True, "valid": not evidence, "leak_evidence": evidence, "usage": usage, "costs": costs,
        "cost_source": "tokens-at-list-price", "parent_models": parsed["models"],
        "gateway": gw, "escalations": [{k: c.get(k) for k in ("status", "model", "backend", "session", "usage")} for c in children],
        "escalation_usage": child_usage, "grade": result_grade, "record_path": str(record_path),
        "log_path": str(log_path), "artifact_path": str(artifact_path),
    }
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(record, indent=1, default=list))
    print("%s [%s] | %s | pass=%s | valid=%s | %.1fs | %d turns | escalations %d | %s"
          % (route_id, route["arm"], task, result_grade["passed"], not evidence, elapsed, usage["calls"], len(children),
             gw["dispatches"] if gw else parsed["models"]))
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--route", action="append", default=[])
    parser.add_argument("--effort", action="append", default=[])
    parser.add_argument("--task", action="append", default=[])
    parser.add_argument("--rep", type=int, default=1)
    parser.add_argument("--limit", type=int, default=600)
    parser.add_argument(
        "--aegis-on-failure", action="store_true",
        help="Retry a failed coding task with the Aegis Method Lite payload in the system prompt.",
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    routes = args.route or [
        "ds41-lunaroute", "ds41-openrouter-floor",
        "claude-sonnet55-direct", "gpt61-sol-direct",
    ]
    tasks = args.task or ["coding/c1_deadlock"]
    efforts = args.effort or ["high"]
    config = load_config()
    failures = 0
    for route_id in routes:
        for task in tasks:
            for effort in efforts:
                try:
                    base = run_one(
                        config, route_id, effort, task, args.rep, args.limit, args.force,
                    )
                    if args.aegis_on_failure and base.get("grade", {}).get("passed") is False:
                        run_one(
                            config, route_id, effort, task, args.rep, args.limit, args.force,
                            aegis_injected=True,
                            parent_record_path=base.get("record_path") or base.get("artifact_path"),
                        )
                except Exception as exc:
                    failures += 1
                    print("FAILED %s | %s | %s: %s" % (route_id, task, effort, exc), file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
