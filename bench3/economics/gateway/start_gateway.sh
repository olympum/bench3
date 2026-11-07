#!/bin/bash
# usage: [BENCH3_ESCALATION=false] start_gateway.sh PORT  -- runs the gateway from ~/nexeval-bench3/llm-proxy-src on 127.0.0.1:PORT
set -euo pipefail
cd ~/nexeval-bench3
BENCH3_LUNAROUTE_KEY=$(python3 -c 'import yaml,os; d=yaml.safe_load(open(os.path.expanduser("~/.dsh/.credentials.yaml"))) or {}; print(d.get("refs", d)["LUNAROUTE_API_KEY"])')
export BENCH3_LUNAROUTE_KEY
cd ${BENCH3_PROXY_SRC:-llm-proxy-src}
exec uv run --frozen python ~/nexeval-bench3/start_gateway.py "$PWD" "$1" ~/nexeval-bench3/gw-$1.duckdb
