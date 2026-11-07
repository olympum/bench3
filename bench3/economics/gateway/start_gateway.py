#!/usr/bin/env python3
"""Run the gateway from a source tree for bench3's ADR 0015 arms on this host, LunaRoute as its only live provider.

    python3 start_gateway.py SRC PORT DB

Adapted from the PLG pilot's launcher (redpanda ~/nexeval/pilot/start_gateway_glm.py): the same selector,
classifier, escalation flag, policy and raised output limits. Differences: the LunaRoute key comes from this
host's DSH credential store (via start_gateway.sh), callers use a fresh local token in ~/nexeval-bench3/.gw-token, and the gateway
listens on 127.0.0.1 only. The LunaRoute key reaches only this process; other providers get a fixture key.
"""
import json, os, secrets, sys

src, port, db = sys.argv[1:4]
home = os.path.expanduser("~")
key = os.environ.pop("BENCH3_LUNAROUTE_KEY")  # set by start_gateway.sh from the DSH credential store
token_path = f"{home}/nexeval-bench3/.gw-token"
if not os.path.exists(token_path):
    fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, secrets.token_urlsafe(32).encode())
    os.close(fd)
token = open(token_path).read().strip()
for name in tuple(os.environ):
    if name.startswith(("AEGIS_LLM_PROXY_", "ANTHROPIC_", "OPENAI_")):
        del os.environ[name]
os.environ.update({
    "AEGIS_LLM_PROXY_LUNAROUTE__API_KEY": key,
    "AEGIS_LLM_PROXY_OPENAI__API_KEY": "fixture-not-a-key",
    "AEGIS_LLM_PROXY_ANTHROPIC__API_KEY": "fixture-not-a-key",
    "AEGIS_LLM_PROXY_SEMANTIC_ROUTING__SELECTOR": "role-table",
    "AEGIS_LLM_PROXY_SEMANTIC_ROUTING__MODE": "enforce",
    "AEGIS_LLM_PROXY_SEMANTIC_ROUTING__TENANT_ALLOWLIST": '["tenant:nexeval"]',
    "AEGIS_LLM_PROXY_SEMANTIC_ROUTING__CLASSIFIER_MODEL": "djev",
    "AEGIS_LLM_PROXY_SEMANTIC_ROUTING__CLASSIFIER_QUESTION_SHA256": "16dab125e6c2b8e93ce423582ac627eca0179168178f49eb50f505faeb523c0f",
    # ADR 0015: the nexus arm runs with escalation off, the nexus-escalate arm with it on.
    "AEGIS_LLM_PROXY_NEXUS_ESCALATION__ENABLED": os.environ.get("BENCH3_ESCALATION", "true"),
    "AEGIS_LLM_PROXY_POLICY__MODE": "enforce",
    "AEGIS_LLM_PROXY_RAISE_OUTPUT_LIMIT_ROUTES": '["lunaroute/deepseek-4.1-flash", "lunaroute/glm-5.3-flash"]',
    "AEGIS_LLM_PROXY_LUNAROUTE__BASE_URL": "https://gw.lunaroute.com/v1",
    "AEGIS_LLM_PROXY_POLICY__USAGE_DB": db,
    "AEGIS_LLM_PROXY_TELEMETRY__USAGE_JOURNAL_ENABLED": "true",
})
os.chdir(src)
sys.path.insert(0, src)
from aegis_llm_proxy.model_catalog import get_default_catalog  # noqa: E402

routes_list = [e.id for e in get_default_catalog().entries
               if e.is_servable and e.target and e.id.startswith(("lunaroute/", "mithran/"))]
os.environ["AEGIS_LLM_PROXY_POLICY__INLINE"] = json.dumps({
    "version": "nexeval-bench3", "rules": [],
    "routing_baseline": {"routes": routes_list, "capability_floor": ["chat"], "zdr_required": False}})
import uvicorn  # noqa: E402
import aegis_llm_proxy.main as main  # noqa: E402
from aegis_llm_proxy.request_context import reset_caller, set_caller  # noqa: E402

# One fixed caller, as in the pilot. Inbound auth is off, so this wrapper checks the local token and sets the
# caller the way InboundAuthMiddleware does.
caller = {"tenant_ref": "tenant:nexeval", "account_ref": "account:nexeval", "subject": "subject:nexeval",
          "scopes": ["llm:aegis-intelligence"]}
app = main.create_app()


async def guarded(scope, receive, send):
    if scope["type"] == "lifespan":
        await app(scope, receive, send)
        return
    if scope["type"] == "http":
        headers = dict(scope["headers"])
        given = headers.get(b"x-api-key", b"") or headers.get(b"authorization", b"").removeprefix(b"Bearer ")
        if given.decode() != token and scope["path"] != "/health":
            await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"error":"bad token"}'})
            return
        scope.setdefault("state", {})["mithran_caller"] = dict(caller)
        reset = set_caller(dict(caller))
        try:
            await app(scope, receive, send)
        finally:
            reset_caller(reset)
        return
    await app(scope, receive, send)


uvicorn.run(guarded, host="127.0.0.1", port=int(port), log_level="warning")
