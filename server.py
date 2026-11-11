#!/usr/bin/env python3
"""
DeepAI Code -> OpenAI-compatible Local Proxy (9Router / Cursor / Cline / SDK ready).

solves:
  1. Auth header translation: Authorization Bearer / x-api-key -> Api-Key
  2. WAF bypass: overrides Node `user-agent: node` with explicit DeepAICode UA
  3. Protocol lane & fingerprint: X-DeepAI-Code-Theos (auto-probed), X-DeepAI-Code-Instance, X-DeepAI-Code-Machine
  4. Two-step /deepai_code/theos check-in (nonce + beacon ack, 5m cache, 6h backoff on check_in_refused)
  5. Explicit stream=false default (DeepAI upstream defaults omitted `stream` to SSE)
  6. Body fallback retry on 400 "This request is not one DeepAI Code sends."
  7. Reasoning normalization: copies `reasoning` -> `reasoning_content` (stream & non-stream)
  8. Responses model bridge: `gpt-6-astra` works via both /v1/responses and /v1/chat/completions
  9. Multi-account round-robin pool + direct DeepAI UUID pass-through from 9Router
"""
import hashlib
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = os.path.expanduser("~")
DATA_DIR = os.environ.get("CONFIG_DIR") or os.path.join(HOME, ".deepai-openai")
CONF_PATH = os.path.join(DATA_DIR, "config.json")
LOG_PATH = os.path.join(DATA_DIR, "proxy.log")

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

PROCESS_START = time.time()
INSTANCE_ID = os.urandom(16).hex()

DEFAULT_SYSTEM_PROMPT = "You are a helpful AI assistant. Answer the user's request directly."
DESKTOP_CHAT_KEYS = {
    "model", "messages", "tools", "tool_choice", "parallel_tool_calls",
    "max_tokens", "max_completion_tokens", "temperature", "top_p", "stop",
    "stream", "stream_options", "store", "seed", "service_tier",
    "reasoning_effort", "prompt_cache_key",
}
LANE_CANDIDATES = ["4", "5", "6", "8", "12", "3", "2"]

FALLBACK_MODELS = [
    {"id": "glm-5.3-flash", "name": "GLM 5.3 Flash", "theosPerRequest": 0, "api": None, "contextWindow": 1048576},
    {"id": "deepseek-v4.1-flash", "name": "DeepSeek V4.1 Flash", "theosPerRequest": 0, "api": None, "contextWindow": 1048576},
    {"id": "mimo-2.6-flash", "name": "MiMo 2.6 Flash", "theosPerRequest": 0, "api": None, "contextWindow": 1048576},
    {"id": "qwen-3.8-flash", "name": "Qwen 3.8 Flash", "theosPerRequest": 0, "api": None, "contextWindow": 1048576},
    {"id": "minimax-m3.1-flash", "name": "MiniMax M3.1 Flash", "theosPerRequest": 0, "api": None, "contextWindow": 204800},
    {"id": "solar-mini-4", "name": "Solar Mini 4", "theosPerRequest": 0, "api": None, "contextWindow": 524288},
    {"id": "gpt-6-luna", "name": "GPT-6 Luna", "theosPerRequest": 0, "api": None, "contextWindow": 1048576},
    {"id": "mimo-2.6-pro", "name": "MiMo 2.6 Pro", "theosPerRequest": 0, "api": None, "contextWindow": 1048576},
    {"id": "crouton-alpha", "name": "Crouton Alpha", "theosPerRequest": 0, "api": None, "contextWindow": 1048576},
    {"id": "glyph-cluster", "name": "Glyph Cluster", "theosPerRequest": 0, "api": None, "contextWindow": 256000},
    {"id": "deepai-cyber", "name": "DeepAI Cyber", "theosPerRequest": 0, "api": None, "contextWindow": 65536},
    {"id": "minimax-m3", "name": "MiniMax M3", "theosPerRequest": 2, "api": None, "contextWindow": 204800},
    {"id": "glm-5.3", "name": "GLM 5.3", "theosPerRequest": 3, "api": None, "contextWindow": 1048576},
    {"id": "kimi-k3", "name": "Kimi K3", "theosPerRequest": 3, "api": None, "contextWindow": 1048576},
    {"id": "muse-spark-1.3", "name": "Muse Spark 1.3", "theosPerRequest": 6, "api": None, "contextWindow": 1048576},
    {"id": "gpt-6.1-sol", "name": "GPT-6.1 Sol", "theosPerRequest": 10, "api": None, "contextWindow": 1048576},
    {"id": "gemini-4-argon", "name": "Gemini 4 Argon", "theosPerRequest": 10, "api": None, "contextWindow": 1048576},
    {"id": "claude-opus-5-5", "name": "Claude Opus 5.5", "theosPerRequest": 15, "api": None, "contextWindow": 1000000},
    {"id": "muse-wonder", "name": "Muse Wonder", "theosPerRequest": 15, "api": None, "contextWindow": 1048576},
    {"id": "qwen-3.8-max-prime", "name": "Qwen 3.8 Max Prime", "theosPerRequest": 15, "api": None, "contextWindow": 1000000},
    {"id": "claude-fable-5-2", "name": "Claude Fable 5.2", "theosPerRequest": 20, "api": None, "contextWindow": 1000000},
    {"id": "gpt-6-astra", "name": "GPT-6 Astra", "theosPerRequest": 50, "api": "openai-responses", "contextWindow": 1048576},
]

DEFAULTS = {
    "host": "0.0.0.0",
    "port": 1417,
    "proxyApiKey": "deepai-local",
    "adminToken": "",
    "allowDirectUuidBearer": True,
    "upstreamBase": "https://api.deepai.org",
    "appVersion": "0.3.32",
    "laneVersion": "auto",
    "userAgent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) DeepAICode/0.3.32 Chrome/134.0.0.0 Electron/35.0.0 Safari/537.36"
    ),
    "accounts": [],
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, 401, "Invalid DeepAI API key (redirected to sign-in)", headers, fp)


OPENER = urllib.request.build_opener(NoRedirect())


def compute_machine_hash():
    raw = ""
    for p in ("/sys/class/dmi/id/product_uuid", "/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            if os.path.exists(p):
                val = open(p, "r", encoding="utf-8", errors="ignore").read().strip().lower()
                if val:
                    raw = val
                    break
        except Exception:
            pass
    if not raw:
        raw = (socket.gethostname() or "deepai-local-machine").strip().lower()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


MACHINE_HASH = compute_machine_hash()
LOCK = threading.RLock()
RR_INDEX = 0

_LANE_CACHE = {"lane": None, "checkedAt": 0.0}
_MODELS_CACHE = {"models": None, "default": "glm-5.3-flash", "fetchedAt": 0.0}
# Per-key check-in & quota state
_KEY_STATE = {}


def log(*args):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + " ".join(str(a) for a in args)
    print(line, file=sys.stderr, flush=True)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def mask_key(k):
    if not k or len(k) < 12:
        return "***"
    return k[:6] + "..." + k[-4:]


def discover_desktop_account():
    candidates = [
        os.environ.get("T3CODE_HOME"),
        os.environ.get("DEEPAI_CODE_HOME"),
        os.path.join(HOME, ".deepai-code"),
    ]
    for base in candidates:
        if not base:
            continue
        for sub in ("userdata/secrets", "secrets", "dev/secrets"):
            for fn in ("deepai-account.bin", "deepai-account-user-managed.bin"):
                p = os.path.join(base, sub, fn)
                if os.path.isfile(p):
                    try:
                        data = json.load(open(p, "r", encoding="utf-8"))
                        ak = (data.get("apiKey") or "").strip()
                        if UUID_RE.match(ak):
                            return {"name": data.get("username") or "desktop", "key": ak, "enabled": True}
                    except Exception:
                        pass
    return None


def load_conf():
    conf = dict(DEFAULTS)
    try:
        if os.path.isfile(CONF_PATH):
            with open(CONF_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f) or {}
                conf.update(loaded)
    except Exception as exc:
        log("config load warning:", exc)
    accts = []
    for i, a in enumerate(conf.get("accounts") or []):
        if isinstance(a, str) and UUID_RE.match(a.strip()):
            accts.append({"name": f"acc-{i+1}", "key": a.strip(), "enabled": True})
        elif isinstance(a, dict):
            k = (a.get("key") or a.get("apiKey") or "").strip()
            if k:
                accts.append({
                    "name": a.get("name") or f"acc-{i+1}",
                    "key": k,
                    "enabled": a.get("enabled", True),
                })
    if not accts:
        desk = discover_desktop_account()
        if desk:
            accts.append(desk)

    # Environment variable overrides (for VPS / systemd / Docker)
    if os.environ.get("HOST"):
        conf["host"] = os.environ["HOST"].strip()
    if os.environ.get("PORT"):
        try:
            conf["port"] = int(os.environ["PORT"].strip())
        except Exception:
            pass
    if os.environ.get("PROXY_API_KEY") is not None and os.environ["PROXY_API_KEY"].strip():
        conf["proxyApiKey"] = os.environ["PROXY_API_KEY"].strip()
    if os.environ.get("ADMIN_TOKEN") is not None and os.environ["ADMIN_TOKEN"].strip():
        conf["adminToken"] = os.environ["ADMIN_TOKEN"].strip()
    env_keys = (os.environ.get("DEEPAI_KEYS") or "").strip()
    if env_keys:
        existing_set = {a["key"] for a in accts}
        for raw_k in env_keys.replace("\n", ",").split(","):
            rk = raw_k.strip()
            if UUID_RE.match(rk) and rk not in existing_set:
                accts.append({"name": f"env-{len(accts)+1}", "key": rk, "enabled": True})
                existing_set.add(rk)

    conf["accounts"] = accts
    return conf


def save_conf(conf):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = CONF_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF_PATH)


CONF = load_conf()


def uptime_seconds():
    return max(0, int(time.time() - PROCESS_START))


def get_key_state(api_key):
    with LOCK:
        st = _KEY_STATE.get(api_key)
        if st is None:
            st = {
                "nonce": "",
                "seconds": 600,
                "ackedNonce": "",
                "noteAt": 0.0,
                "attemptAt": 0.0,
                "lastRelay": 0.0,
                "refusedUntil": 0.0,
                "theos": None,
                "usage": None,
                "blockedReason": "",
            }
            _KEY_STATE[api_key] = st
        return st


def get_lane(force=False):
    explicit = str(CONF.get("laneVersion") or "auto").strip().lower()
    if explicit and explicit != "auto":
        return explicit
    with LOCK:
        if not force and _LANE_CACHE["lane"] and (time.time() - _LANE_CACHE["checkedAt"] < 1800):
            return _LANE_CACHE["lane"]
    base = CONF["upstreamBase"].rstrip("/")
    for cand in LANE_CANDIDATES:
        req = urllib.request.Request(
            base + "/deepai_code/models",
            headers={
                "User-Agent": CONF["userAgent"],
                "Accept": "application/json",
                "X-DeepAI-Code-Theos": cand,
                "X-DeepAI-Code-Instance": INSTANCE_ID,
                "X-DeepAI-Code-Machine": MACHINE_HASH,
            },
            method="GET",
        )
        try:
            with OPENER.open(req, timeout=12) as resp:
                raw = resp.read(2 << 20)
                data = json.loads(raw)
                models = data.get("models")
                if resp.status == 200 and isinstance(models, list) and models:
                    with LOCK:
                        _LANE_CACHE["lane"] = cand
                        _LANE_CACHE["checkedAt"] = time.time()
                        _MODELS_CACHE["models"] = models
                        _MODELS_CACHE["default"] = data.get("default") or "glm-5.3-flash"
                        _MODELS_CACHE["fetchedAt"] = time.time()
                    log(f"lane auto-detected: {cand} ({len(models)} models)")
                    return cand
        except urllib.error.HTTPError as e:
            if e.code == 426:
                continue
        except Exception:
            break
    with LOCK:
        fallback = _LANE_CACHE["lane"] or "4"
        _LANE_CACHE["lane"] = fallback
        _LANE_CACHE["checkedAt"] = time.time()
        return fallback


def fetch_models(force=False):
    with LOCK:
        if not force and _MODELS_CACHE["models"] and (time.time() - _MODELS_CACHE["fetchedAt"] < 600):
            return list(_MODELS_CACHE["models"]), _MODELS_CACHE["default"]
    lane = get_lane(force=force)
    with LOCK:
        if not force and _MODELS_CACHE["models"] and (time.time() - _MODELS_CACHE["fetchedAt"] < 30):
            return list(_MODELS_CACHE["models"]), _MODELS_CACHE["default"]
    base = CONF["upstreamBase"].rstrip("/")
    req = urllib.request.Request(
        base + "/deepai_code/models",
        headers={
            "User-Agent": CONF["userAgent"],
            "Accept": "application/json",
            "X-DeepAI-Code-Theos": lane,
            "X-DeepAI-Code-Instance": INSTANCE_ID,
            "X-DeepAI-Code-Machine": MACHINE_HASH,
        },
        method="GET",
    )
    try:
        with OPENER.open(req, timeout=15) as resp:
            data = json.loads(resp.read(2 << 20))
            models = data.get("models")
            if isinstance(models, list) and models:
                with LOCK:
                    _MODELS_CACHE["models"] = models
                    _MODELS_CACHE["default"] = data.get("default") or "glm-5.3-flash"
                    _MODELS_CACHE["fetchedAt"] = time.time()
                return list(models), _MODELS_CACHE["default"]
    except Exception as exc:
        log("fetch_models fallback:", exc)
    with LOCK:
        return list(_MODELS_CACHE["models"] or FALLBACK_MODELS), _MODELS_CACHE["default"]


def resolve_model_meta(raw_model):
    models, default_id = fetch_models()
    if not raw_model:
        raw_model = default_id
    clean = str(raw_model).strip()
    by_id = {m.get("id"): m for m in models if isinstance(m, dict) and m.get("id")}
    if clean in by_id:
        return by_id[clean]
    if "/" in clean:
        tail = clean.split("/")[-1]
        if tail in by_id:
            return by_id[tail]
    return {"id": clean, "name": clean, "api": "openai-responses" if clean == "gpt-6-astra" else None}


def build_upstream_headers(api_key, lane=None, affinity=None, extra=None):
    h = {
        "User-Agent": CONF["userAgent"],
        "Api-Key": api_key,
        "X-DeepAI-Code-Theos": lane or get_lane(),
        "X-DeepAI-Code-Instance": INSTANCE_ID,
        "X-DeepAI-Code-Machine": MACHINE_HASH,
    }
    if affinity:
        h["X-Session-Affinity"] = str(affinity)
    if extra:
        h.update(extra)
    return h


def call_theos_once(api_key):
    st = get_key_state(api_key)
    with LOCK:
        sent_nonce = st["nonce"]
        ttl = st["seconds"] or 600
        pi = 1 if (st["lastRelay"] > 0 and (time.time() - st["lastRelay"]) < ttl) else 0
    beacon = f"v={CONF['appVersion']};up={uptime_seconds()};pi={pi}"
    extra = {"Accept": "application/json", "X-DeepAI-Code-Beacon": beacon}
    if sent_nonce:
        extra["X-DeepAI-Code-Check-In"] = sent_nonce
    url = CONF["upstreamBase"].rstrip("/") + "/deepai_code/theos"
    req = urllib.request.Request(url, headers=build_upstream_headers(api_key, extra=extra), method="GET")
    try:
        with OPENER.open(req, timeout=10) as resp:
            raw = resp.read(1 << 20)
            data = json.loads(raw)
            with LOCK:
                if sent_nonce:
                    st["ackedNonce"] = sent_nonce
                ci = data.get("check_in") or {}
                if isinstance(ci, dict) and ci.get("nonce"):
                    st["nonce"] = ci["nonce"]
                    st["seconds"] = int(ci.get("seconds") or 600)
                    st["noteAt"] = time.time()
                st["theos"] = data
                st["blockedReason"] = ""
            return 200, data
    except urllib.error.HTTPError as e:
        raw = e.read(1 << 20)
        try:
            err_json = json.loads(raw)
        except Exception:
            err_json = {"raw": raw.decode("utf-8", "replace")[:300]}
        code_str = ((err_json.get("error") or {}).get("code") or "") if isinstance(err_json, dict) else ""
        with LOCK:
            if sent_nonce:
                st["ackedNonce"] = sent_nonce
            if isinstance(err_json, dict):
                ci = err_json.get("check_in") or {}
                if isinstance(ci, dict) and ci.get("nonce"):
                    st["nonce"] = ci["nonce"]
                    st["seconds"] = int(ci.get("seconds") or 600)
                    st["noteAt"] = time.time()
            if code_str == "check_in_refused" or "too many times today" in str(err_json).lower():
                st["refusedUntil"] = time.time() + 6 * 3600
                log(f"theos check-in rate-limited for {mask_key(api_key)}, pausing /theos for 6h (chat unaffected)")
            elif code_str == "social_login_required":
                st["blockedReason"] = "social_login_required"
        return e.code, err_json
    except Exception as exc:
        log(f"theos network warning ({mask_key(api_key)}):", exc)
        return 0, {"error": str(exc)}


def ensure_checkin(api_key, force=False):
    st = get_key_state(api_key)
    now = time.time()
    with LOCK:
        if not force and st["refusedUntil"] > now:
            return st["theos"]
        has_nonce = bool(st["nonce"])
        need_ack = has_nonce and (st["nonce"] != st["ackedNonce"])
        half_ttl = max(60, (st["seconds"] or 600) / 2.0)
        if not force and has_nonce and not need_ack and (now - st["noteAt"] < half_ttl):
            return st["theos"]
        if not force and not need_ack and st["attemptAt"] > 0 and (now - st["attemptAt"] < 30):
            return st["theos"]
        st["attemptAt"] = now

    status, data = call_theos_once(api_key)
    # Complete two-step initial nonce ack immediately on first check-in
    with LOCK:
        need_initial_ack = bool(st["nonce"]) and (st["nonce"] != st["ackedNonce"]) and st["refusedUntil"] <= time.time()
        if need_initial_ack:
            st["attemptAt"] = time.time()
    if status == 200 and need_initial_ack:
        _, data2 = call_theos_once(api_key)
        return data2
    return data


def mark_relay(api_key):
    st = get_key_state(api_key)
    with LOCK:
        st["lastRelay"] = time.time()


def extract_client_token(headers):
    auth = (headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer" + " "):
        return auth[7:].strip()
    for hk in ("x-api-key", "Api-Key", "api-key"):
        v = (headers.get(hk) or "").strip()
        if v:
            return v
    return ""


def select_upstream_keys(client_token):
    """Returns (mode, [api_keys]) or raises PermissionError."""
    if client_token and CONF.get("allowDirectUuidBearer", True) and UUID_RE.match(client_token):
        return "direct", [client_token]
    expected = (CONF.get("proxyApiKey") or "").strip()
    if expected and client_token != expected:
        raise PermissionError("Invalid API key. Pass proxyApiKey ('%s') or a valid DeepAI UUID key." % expected)
    with LOCK:
        global RR_INDEX
        enabled = [a["key"] for a in (CONF.get("accounts") or []) if a.get("enabled", True) and a.get("key")]
        if not enabled:
            raise RuntimeError("No active DeepAI accounts configured in ~/.deepai-openai/config.json")
        n = len(enabled)
        start = RR_INDEX % n
        RR_INDEX = (RR_INDEX + 1) % n
        ordered = [enabled[(start + i) % n] for i in range(n)]
    return "pool", ordered


def chat_body_fallback(payload):
    msgs = payload.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return None
    strict = {k: v for k, v in payload.items() if k in DESKTOP_CHAT_KEYS}
    has_sys = any(isinstance(m, dict) and m.get("role") in ("system", "developer") for m in msgs)
    if not has_sys:
        strict["messages"] = [{"role": "system", "content": DEFAULT_SYSTEM_PROMPT}] + list(msgs)
    return strict


def add_reasoning_content(obj):
    if not isinstance(obj, dict) or "reasoning_content" in obj:
        return
    r = obj.get("reasoning")
    if isinstance(r, str) and r:
        obj["reasoning_content"] = r


def normalize_chat_response(data, public_model):
    if not isinstance(data, dict):
        return data
    if public_model:
        data["model"] = public_model
    for ch in data.get("choices") or []:
        if isinstance(ch, dict):
            add_reasoning_content(ch.get("message"))
    return data


def normalize_chat_chunk(chunk, public_model):
    if not isinstance(chunk, dict):
        return chunk
    if public_model:
        chunk["model"] = public_model
    for ch in chunk.get("choices") or []:
        if isinstance(ch, dict):
            add_reasoning_content(ch.get("delta"))
    return chunk


def chat_to_responses_payload(chat_payload, model_id):
    msgs = chat_payload.get("messages") or []
    sys_parts = []
    inp = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        role = m.get("role") or "user"
        content = m.get("content")
        if role in ("system", "developer"):
            if isinstance(content, str) and content.strip():
                sys_parts.append(content.strip())
            elif isinstance(content, list):
                txt = "\n".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("text"))
                if txt.strip():
                    sys_parts.append(txt.strip())
        elif role == "tool":
            inp.append({
                "type": "function_call_output",
                "call_id": m.get("tool_call_id") or "call_0",
                "output": content if isinstance(content, str) else json.dumps(content or ""),
            })
        elif role == "assistant" and m.get("tool_calls"):
            if content:
                inp.append({"type": "message", "role": "assistant", "content": content})
            for tc in m.get("tool_calls") or []:
                fn = (tc.get("function") or {}) if isinstance(tc, dict) else {}
                inp.append({
                    "type": "function_call",
                    "call_id": tc.get("id") or "call_0",
                    "name": fn.get("name") or "",
                    "arguments": fn.get("arguments") or "{}",
                })
        else:
            if isinstance(content, list):
                parts = []
                for p in content:
                    if not isinstance(p, dict):
                        continue
                    ptype = p.get("type")
                    if ptype == "text":
                        txt_type = "output_text" if role == "assistant" else "input_text"
                        parts.append({"type": txt_type, "text": p.get("text") or ""})
                    elif ptype == "image_url":
                        iu = p.get("image_url")
                        u = iu.get("url") if isinstance(iu, dict) else str(iu or "")
                        if u:
                            parts.append({"type": "input_image", "image_url": u})
                inp.append({"type": "message", "role": role, "content": parts})
            else:
                inp.append({"type": "message", "role": role, "content": str(content or "")})

    out = {
        "model": model_id,
        "instructions": "\n\n".join(sys_parts) if sys_parts else DEFAULT_SYSTEM_PROMPT,
        "input": inp or [{"type": "message", "role": "user", "content": ""}],
        "stream": bool(chat_payload.get("stream", False)),
    }
    for k_src, k_dst in (("temperature", "temperature"), ("top_p", "top_p"), ("prompt_cache_key", "prompt_cache_key")):
        if k_src in chat_payload:
            out[k_dst] = chat_payload[k_src]
    max_tok = chat_payload.get("max_completion_tokens") or chat_payload.get("max_tokens")
    if isinstance(max_tok, int) and max_tok > 0:
        out["max_output_tokens"] = max_tok
    if chat_payload.get("reasoning_effort"):
        out["reasoning"] = {"effort": str(chat_payload["reasoning_effort"])}
    if isinstance(chat_payload.get("tools"), list) and chat_payload["tools"]:
        rtools = []
        for t in chat_payload["tools"]:
            if isinstance(t, dict) and t.get("type") == "function" and isinstance(t.get("function"), dict):
                fn = t["function"]
                rt = {"type": "function", "name": fn.get("name") or ""}
                if fn.get("description"):
                    rt["description"] = fn["description"]
                if "parameters" in fn:
                    rt["parameters"] = fn["parameters"]
                rtools.append(rt)
        if rtools:
            out["tools"] = rtools
    return out


def responses_obj_to_chat(robj, public_model):
    text_parts = []
    reasoning_parts = []
    tool_calls = []
    for item in robj.get("output") or []:
        if not isinstance(item, dict):
            continue
        itype = item.get("type")
        if itype == "message":
            for c in item.get("content") or []:
                if isinstance(c, dict) and c.get("text"):
                    text_parts.append(c["text"])
        elif itype == "reasoning":
            for s in item.get("summary") or []:
                if isinstance(s, dict) and s.get("text"):
                    reasoning_parts.append(s["text"])
        elif itype == "function_call":
            tool_calls.append({
                "id": item.get("call_id") or item.get("id") or f"call_{len(tool_calls)}",
                "type": "function",
                "function": {
                    "name": item.get("name") or "",
                    "arguments": item.get("arguments") or "{}",
                },
            })
    content_str = "".join(text_parts) or robj.get("output_text") or ""
    msg = {"role": "assistant", "content": content_str if (content_str or not tool_calls) else None}
    if reasoning_parts:
        rtxt = "\n".join(reasoning_parts)
        msg["reasoning"] = rtxt
        msg["reasoning_content"] = rtxt
    finish = "stop"
    if tool_calls:
        msg["tool_calls"] = tool_calls
        finish = "tool_calls"
    u = robj.get("usage") or {}
    pt = u.get("input_tokens") or 0
    ct = u.get("output_tokens") or 0
    return {
        "id": robj.get("id") or f"chatcmpl-{int(time.time()*1000)}",
        "object": "chat.completion",
        "created": int(robj.get("created_at") or time.time()),
        "model": public_model,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "total_tokens": u.get("total_tokens") or (pt + ct),
        },
    }


def parse_retry_after(headers, fallback=3):
    raw = (headers.get("Retry-After") or "").strip() if headers else ""
    try:
        secs = int(raw)
        return max(1, min(30, secs))
    except Exception:
        return fallback


def open_upstream_post(path, payload_dict, api_keys, affinity=None, is_chat=True):
    """Opens upstream HTTP response with automatic lane refresh, body-shape fallback, and account pool retry."""
    base = CONF["upstreamBase"].rstrip("/")
    last_status = 502
    last_body = b'{"error":{"message":"upstream unreachable","type":"upstream_error"}}'
    last_headers = {}

    for idx, ak in enumerate(api_keys):
        ensure_checkin(ak)
        cur_payload = dict(payload_dict)
        for attempt in range(2):
            lane = get_lane()
            hdrs = build_upstream_headers(ak, lane=lane, affinity=affinity, extra={
                "Content-Type": "application/json",
                "Accept": "text/event-stream" if cur_payload.get("stream") else "application/json",
            })
            raw_req = json.dumps(cur_payload).encode("utf-8")
            req = urllib.request.Request(base + path, data=raw_req, headers=hdrs, method="POST")
            try:
                resp = OPENER.open(req, timeout=180)
                mark_relay(ak)
                return resp, ak
            except urllib.error.HTTPError as e:
                err_bytes = e.read(1 << 20)
                last_status = e.code
                last_body = err_bytes
                last_headers = dict(e.headers.items()) if e.headers else {}
                body_lower = err_bytes.decode("utf-8", "ignore").lower()

                if e.code == 426 and attempt == 0:
                    log("426 lane_version_unsupported -> re-probing lane")
                    get_lane(force=True)
                    continue

                if e.code == 400 and "not one deepai code sends" in body_lower and attempt == 0:
                    if is_chat:
                        fb = chat_body_fallback(cur_payload)
                        if fb is not None:
                            log("400 shape check -> retrying with desktop chat_body_fallback")
                            cur_payload = fb
                            continue
                    else:
                        if not cur_payload.get("instructions"):
                            cur_payload["instructions"] = DEFAULT_SYSTEM_PROMPT
                            continue

                # Convert 409 session_busy -> 429
                if e.code == 409 and "session_busy" in body_lower:
                    last_status = 429
                    ra = parse_retry_after(e.headers, 3)
                    last_headers["Retry-After"] = str(ra)
                    if idx + 1 < len(api_keys):
                        log(f"409 session_busy on {mask_key(ak)}, failing over to next account")
                        break
                    if attempt == 0:
                        time.sleep(min(ra, 3))
                        continue

                # Pool failover on auth/quota/5xx
                if idx + 1 < len(api_keys) and (e.code in (401, 403, 409, 429) or e.code >= 500):
                    log(f"HTTP {e.code} on {mask_key(ak)}, failing over to next account")
                    break
                break
            except Exception as exc:
                last_status = 502
                last_body = json.dumps({"error": {"message": str(exc), "type": "upstream_error"}}).encode("utf-8")
                if idx + 1 < len(api_keys):
                    continue
                break

    return (last_status, last_body, last_headers), None


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DeepAI Code Local Proxy</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; max-width: 920px; margin: 28px auto; padding: 0 18px; line-height: 1.5; }
  h1 { font-size: 1.4rem; margin-bottom: 4px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 14px 0; }
  code, pre { background: #0d1117; border: 1px solid #30363d; border-radius: 5px; padding: 2px 6px; font-family: ui-monospace, monospace; font-size: 0.9rem; }
  pre { padding: 10px; overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid #21262d; }
  .free { color: #3fb950; font-weight: 600; }
  .paid { color: #d29922; }
  input, button { background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: 5px; padding: 6px 10px; }
  button { background: #238636; border-color: #2ea043; cursor: pointer; font-weight: 600; }
  button.del { background: #da3633; border-color: #f85149; padding: 3px 8px; font-size: 0.8rem; }
</style>
</head>
<body>
  <h1>DeepAI Code -&gt; OpenAI Compatible Proxy</h1>
  <div id="authCard" class="card" style="display:none;border-color:#d29922">
    <b>Admin Login Required (Remote / VPS Mode)</b>
    <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
      <input id="admTok" type="password" placeholder="Admin / Proxy API Key (default: deepai-local)" style="flex:1;min-width:260px">
      <button onclick="saveTok()">Unlock Dashboard</button>
    </div>
  </div>
  <div class="card">
    <div><b>9Router / OpenAI Base URL:</b> <code id="burl"></code></div>
    <div style="margin-top:6px"><b>API Key (di 9Router):</b> langsung paste UUID key DeepAI kamu ATAU isi <code>proxyApiKey</code> (untuk pakai pool akun di bawah).</div>
    <div style="margin-top:6px" id="hstat">Loading status...</div>
  </div>
  <div class="card">
    <b>Accounts Pool &amp; Theos Quota</b>
    <table id="acctTbl" style="margin-top:8px"><thead><tr><th>Name</th><th>Key</th><th>Theos Balance</th><th>Action</th></tr></thead><tbody></tbody></table>
    <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
      <input id="aname" placeholder="Label (optional)" style="width:150px">
      <input id="akey" placeholder="DeepAI UUID API Key" style="flex:1;min-width:280px">
      <button onclick="addAcct()">+ Add Key</button>
      <button onclick="loadStatus(1)" style="background:#1f6feb;border-color:#388bfd">Refresh Quota</button>
      <button onclick="testChat()" style="background:#8957e5;border-color:#a371f7">Test Chat</button>
    </div>
    <div id="testOut" style="margin-top:8px;font-size:0.88rem;color:#8b949e"></div>
  </div>
  <div class="card">
    <b>Available Models (<span id="mcnt">0</span>)</b>
    <table id="modTbl" style="margin-top:8px"><thead><tr><th>Model ID</th><th>Name</th><th>Context</th><th>Cost</th></tr></thead><tbody></tbody></table>
  </div>
<script>
document.getElementById('burl').textContent = location.origin + '/v1';
function getHeaders(json=false) {
  const h = {};
  if (json) h['Content-Type'] = 'application/json';
  const t = localStorage.getItem('deepai_adm_tok') || '';
  if (t) h['X-Admin-Token'] = t;
  return h;
}
function saveTok() {
  localStorage.setItem('deepai_adm_tok', document.getElementById('admTok').value.trim());
  loadStatus(0);
}
async function loadStatus(refresh=0) {
  const r = await fetch('/api/status' + (refresh ? '?refresh=1' : ''), {headers: getHeaders()});
  if (r.status === 401 || r.status === 403) {
    document.getElementById('authCard').style.display = 'block';
    document.getElementById('hstat').textContent = 'Locked — enter your Proxy / Admin Token above.';
    return;
  }
  document.getElementById('authCard').style.display = 'none';
  const d = await r.json();
  document.getElementById('hstat').textContent = `Lane: ${d.lane} | Machine: ${d.machine.slice(0,12)}... | Uptime: ${d.uptime}s`;
  const tb = document.querySelector('#acctTbl tbody');
  tb.innerHTML = '';
  for (const a of d.accounts) {
    const th = a.theos ? `${a.theos.balance} / ${a.theos.granted} Theos` : (a.blocked || 'unchecked');
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${a.name}</td><td><code>${a.maskedKey}</code></td><td>${th}</td><td><button class="del" onclick="delAcct('${a.maskedKey}')">Remove</button></td>`;
    tb.appendChild(tr);
  }
  document.getElementById('mcnt').textContent = d.models.length;
  const mt = document.querySelector('#modTbl tbody');
  mt.innerHTML = '';
  for (const m of d.models) {
    const c = Number(m.theosPerRequest || 0);
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><code>${m.id}</code></td><td>${m.name || m.id}</td><td>${(m.contextWindow||0).toLocaleString()}</td><td class="${c===0?'free':'paid'}">${c===0?'FREE (0 Theos)':c+' Theos/req'}</td>`;
    mt.appendChild(tr);
  }
}
async function addAcct() {
  const name = document.getElementById('aname').value.trim();
  const key = document.getElementById('akey').value.trim();
  if (!key) return;
  await fetch('/api/accounts', {method:'POST', headers: getHeaders(true), body:JSON.stringify({action:'add', name, key})});
  document.getElementById('akey').value = '';
  loadStatus(1);
}
async function delAcct(masked) {
  await fetch('/api/accounts', {method:'POST', headers: getHeaders(true), body:JSON.stringify({action:'remove', maskedKey:masked})});
  loadStatus(0);
}
async function testChat() {
  const el = document.getElementById('testOut');
  el.textContent = 'Testing glm-5.3-flash...';
  const tok = localStorage.getItem('deepai_adm_tok') || 'deepai-local';
  const r = await fetch('/v1/chat/completions', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'x-api-key': tok},
    body: JSON.stringify({model: 'glm-5.3-flash', messages: [{role: 'user', content: 'Reply PONG only.'}]})
  });
  const d = await r.json();
  el.textContent = r.ok ? `200 OK -> ${d.choices[0].message.content}` : `Error ${r.status}: ${JSON.stringify(d)}`;
}
loadStatus(0);
</script>
</body>
</html>
"""


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log(self.address_string(), fmt % args)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, Api-Key, x-api-key, X-Admin-Token, X-Session-Affinity")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _admin_ok(self):
        explicit_adm = (CONF.get("adminToken") or "").strip()
        client_ip = (self.client_address[0] or "")
        is_loopback = client_ip in ("127.0.0.1", "::1") or client_ip.startswith("127.")
        if is_loopback and not explicit_adm:
            return True
        expected = explicit_adm or (CONF.get("proxyApiKey") or "").strip()
        if not expected:
            return is_loopback
        got = (self.headers.get("X-Admin-Token") or "").strip() or extract_client_token(self.headers)
        return got == expected

    def _send_bytes(self, code, raw, content_type="application/json", extra_headers=None):
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra_headers or {}).items():
            if k.lower() in ("Retry-After".lower(),):
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _json(self, code, obj, extra_headers=None):
        self._send_bytes(code, json.dumps(obj).encode("utf-8"), "application/json", extra_headers=extra_headers)

    def _err(self, code, msg, etype="upstream_error", extra_headers=None):
        self._json(code, {"error": {"message": msg, "type": etype, "code": code}}, extra_headers=extra_headers)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path, _, qs = self.path.partition("?")
        if path == "/":
            return self._send_bytes(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")

        if path == "/health":
            models, default_id = fetch_models()
            return self._json(200, {
                "ok": True,
                "port": CONF["port"],
                "lane": get_lane(),
                "machine": MACHINE_HASH,
                "defaultModel": default_id,
                "modelCount": len(models),
                "accountCount": len([a for a in CONF.get("accounts") or [] if a.get("enabled", True)]),
                "uptimeSeconds": uptime_seconds(),
            })

        if path == "/api/status":
            if not self._admin_ok():
                return self._err(401, "Admin token required", "authentication_error")
            refresh = "refresh=1" in qs
            models, default_id = fetch_models(force=refresh)
            acct_rows = []
            for a in CONF.get("accounts") or []:
                ak = a.get("key") or ""
                if refresh and ak:
                    ensure_checkin(ak, force=True)
                st = get_key_state(ak) if ak else {}
                acct_rows.append({
                    "name": a.get("name") or "acc",
                    "maskedKey": mask_key(ak),
                    "enabled": a.get("enabled", True),
                    "theos": st.get("theos"),
                    "blocked": st.get("blockedReason") or "",
                })
            return self._json(200, {
                "lane": get_lane(),
                "machine": MACHINE_HASH,
                "uptime": uptime_seconds(),
                "defaultModel": default_id,
                "accounts": acct_rows,
                "models": models,
            })

        if path in ("/v1/theos", "/theos"):
            tok = extract_client_token(self.headers)
            try:
                _, keys = select_upstream_keys(tok)
            except PermissionError as exc:
                return self._err(401, str(exc), "authentication_error")
            except RuntimeError as exc:
                return self._err(503, str(exc), "server_error")
            data = ensure_checkin(keys[0])
            st = get_key_state(keys[0])
            return self._json(200, {"key": mask_key(keys[0]), "theos": data or st.get("theos")})

        if path in ("/v1/models", "/models", "/deepai_code/models"):
            tok = extract_client_token(self.headers)
            if tok:
                expected = (CONF.get("proxyApiKey") or "").strip()
                if expected and tok != expected and not (CONF.get("allowDirectUuidBearer", True) and UUID_RE.match(tok)):
                    return self._err(401, "Invalid API key", "authentication_error")
            models, _ = fetch_models()
            now_ts = int(time.time())
            data_list = []
            for m in models:
                if not isinstance(m, dict) or not m.get("id"):
                    continue
                data_list.append({
                    "id": m["id"],
                    "object": "model",
                    "created": now_ts,
                    "owned_by": "deepai-code",
                    "context_window": m.get("contextWindow"),
                    "max_tokens": m.get("maxTokens"),
                    "theos_per_request": m.get("theosPerRequest", 0),
                })
            return self._json(200, {"object": "list", "data": data_list})

        return self._err(404, f"Unknown endpoint: {path}", "invalid_request_error")

    def do_POST(self):
        path = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        raw_in = self.rfile.read(n) if n > 0 else b"{}"
        try:
            payload = json.loads(raw_in)
        except Exception as exc:
            return self._err(400, f"Invalid JSON body: {exc}", "invalid_request_error")

        if path == "/api/accounts":
            if not self._admin_ok():
                return self._err(401, "Admin token required", "authentication_error")
            action = payload.get("action")
            with LOCK:
                accts = list(CONF.get("accounts") or [])
                if action == "add":
                    k = (payload.get("key") or "").strip()
                    if not UUID_RE.match(k):
                        return self._err(400, "Key must be a valid UUID (8-4-4-4-12)", "invalid_request_error")
                    if not any(a.get("key") == k for a in accts):
                        accts.append({"name": payload.get("name") or f"acc-{len(accts)+1}", "key": k, "enabled": True})
                    CONF["accounts"] = accts
                    save_conf(CONF)
                elif action == "remove":
                    mk = payload.get("maskedKey")
                    CONF["accounts"] = [a for a in accts if mask_key(a.get("key") or "") != mk]
                    save_conf(CONF)
            return self._json(200, {"ok": True, "count": len(CONF["accounts"])})

        tok = extract_client_token(self.headers)
        try:
            _, api_keys = select_upstream_keys(tok)
        except PermissionError as exc:
            return self._err(401, str(exc), "authentication_error")
        except RuntimeError as exc:
            return self._err(503, str(exc), "server_error")

        if path in ("/v1/chat/completions", "/chat/completions", "/deepai_code/chat/completions"):
            return self._handle_chat(payload, api_keys)

        if path in ("/v1/responses", "/responses", "/deepai_code/responses"):
            return self._handle_responses(payload, api_keys)

        return self._err(404, f"Unknown endpoint: {path}", "invalid_request_error")

    def _stream_sse_chat(self, upstream_resp, public_model):
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        done_sent = False
        data_lines = []
        try:
            while True:
                line = upstream_resp.readline()
                if not line:
                    break
                s = line.decode("utf-8", "replace").rstrip("\r\n")
                if s.startswith(":"):
                    self.wfile.write((s + "\n\n").encode("utf-8"))
                    self.wfile.flush()
                    continue
                if s.startswith("data:"):
                    data_lines.append(s[5:].lstrip(" "))
                    continue
                if s == "" and data_lines:
                    joined = "\n".join(data_lines)
                    data_lines = []
                    if joined.strip() == "[DONE]":
                        self.wfile.write(b"data: [DONE]\n\n")
                        self.wfile.flush()
                        done_sent = True
                        break
                    try:
                        obj = json.loads(joined)
                        normalize_chat_chunk(obj, public_model)
                        out_line = "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"
                    except Exception:
                        out_line = "data: " + joined + "\n\n"
                    self.wfile.write(out_line.encode("utf-8"))
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            log("SSE stream error:", exc)
        finally:
            try:
                upstream_resp.close()
            except Exception:
                pass
            if not done_sent:
                try:
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except Exception:
                    pass

    def _stream_responses_as_chat(self, upstream_resp, public_model):
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        cid = f"chatcmpl-{int(time.time()*1000)}"
        created = int(time.time())
        base = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": public_model}

        def emit(delta, finish=None, usage=None):
            ch = dict(base, choices=[{"index": 0, "delta": delta, "finish_reason": finish}])
            if usage:
                ch["usage"] = usage
            self.wfile.write(("data: " + json.dumps(ch, ensure_ascii=False) + "\n\n").encode("utf-8"))
            self.wfile.flush()

        try:
            emit({"role": "assistant"})
            data_lines = []
            finish_sent = False
            while True:
                line = upstream_resp.readline()
                if not line:
                    break
                s = line.decode("utf-8", "replace").rstrip("\r\n")
                if s.startswith("data:"):
                    data_lines.append(s[5:].lstrip(" "))
                    continue
                if s == "" and data_lines:
                    joined = "\n".join(data_lines)
                    data_lines = []
                    if joined.strip() == "[DONE]":
                        break
                    try:
                        ev = json.loads(joined)
                    except Exception:
                        continue
                    etype = ev.get("type") or ""
                    if etype == "response.output_text.delta" and ev.get("delta"):
                        emit({"content": ev["delta"]})
                    elif etype in ("response.reasoning_summary_text.delta", "response.reasoning_text.delta") and ev.get("delta"):
                        emit({"reasoning": ev["delta"], "reasoning_content": ev["delta"]})
                    elif etype == "response.completed":
                        resp_obj = ev.get("response") or {}
                        conv = responses_obj_to_chat(resp_obj, public_model)
                        msg = ((conv.get("choices") or [{}])[0]).get("message") or {}
                        if msg.get("tool_calls"):
                            emit({"tool_calls": [dict(tc, index=i) for i, tc in enumerate(msg["tool_calls"])]})
                            emit({}, finish="tool_calls", usage=conv.get("usage"))
                        else:
                            emit({}, finish="stop", usage=conv.get("usage"))
                        finish_sent = True
            if not finish_sent:
                emit({}, finish="stop")
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            try:
                upstream_resp.close()
            except Exception:
                pass
            try:
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except Exception:
                pass

    def _handle_chat(self, payload, api_keys):
        msgs = payload.get("messages")
        if not isinstance(msgs, list) or not msgs:
            return self._err(400, "messages must be a non-empty array", "invalid_request_error")

        public_model = payload.get("model") or "glm-5.3-flash"
        meta = resolve_model_meta(public_model)
        upstream_model = meta["id"]
        stream = bool(payload.get("stream", False))
        affinity = self.headers.get("X-Session-Affinity") or payload.get("prompt_cache_key") or payload.get("user")

        # Bridge Responses-only model (e.g. gpt-6-astra) transparently
        if meta.get("api") == "openai-responses":
            rpayload = chat_to_responses_payload(payload, upstream_model)
            res, ak = open_upstream_post("/deepai_code/responses", rpayload, api_keys, affinity=affinity, is_chat=False)
            if ak is None:
                code, err_raw, hdrs = res
                return self._send_bytes(code, err_raw, "application/json", extra_headers=hdrs)
            if stream:
                return self._stream_responses_as_chat(res, public_model)
            raw_resp = res.read(32 << 20)
            res.close()
            try:
                robj = json.loads(raw_resp)
            except Exception:
                return self._err(502, "Upstream /responses returned invalid JSON")
            return self._json(200, responses_obj_to_chat(robj, public_model))

        up_payload = dict(payload)
        up_payload["model"] = upstream_model
        up_payload["stream"] = stream  # MUST be explicit: DeepAI defaults omitted stream to SSE

        res, ak = open_upstream_post("/deepai_code/chat/completions", up_payload, api_keys, affinity=affinity, is_chat=True)
        if ak is None:
            code, err_raw, hdrs = res
            return self._send_bytes(code, err_raw, "application/json", extra_headers=hdrs)

        if stream:
            return self._stream_sse_chat(res, public_model)

        raw_resp = res.read(32 << 20)
        res.close()
        try:
            out = json.loads(raw_resp)
        except Exception:
            log("invalid JSON from upstream chat:", raw_resp[:200])
            return self._err(502, "Upstream returned non-JSON response")
        normalize_chat_response(out, public_model)
        return self._json(200, out)

    def _handle_responses(self, payload, api_keys):
        public_model = payload.get("model") or "gpt-6-astra"
        meta = resolve_model_meta(public_model)
        stream = bool(payload.get("stream", False))
        affinity = self.headers.get("X-Session-Affinity") or payload.get("prompt_cache_key")

        up_payload = dict(payload)
        up_payload["model"] = meta["id"]
        up_payload["stream"] = stream
        if not up_payload.get("instructions"):
            up_payload["instructions"] = DEFAULT_SYSTEM_PROMPT

        res, ak = open_upstream_post("/deepai_code/responses", up_payload, api_keys, affinity=affinity, is_chat=False)
        if ak is None:
            code, err_raw, hdrs = res
            return self._send_bytes(code, err_raw, "application/json", extra_headers=hdrs)

        if stream:
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                while True:
                    chunk = res.read(4096)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                res.close()
            return

        raw_resp = res.read(32 << 20)
        res.close()
        return self._send_bytes(200, raw_resp, "application/json")


class ThreadedHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.isfile(CONF_PATH):
        save_conf(CONF)
    else:
        try:
            os.chmod(CONF_PATH, 0o600)
        except Exception:
            pass

    lane = get_lane()
    models, default_id = fetch_models()
    host = CONF["host"]
    port = int(CONF["port"])
    log(
        f"deepai-proxy starting on http://{host}:{port}/v1 | lane={lane} | "
        f"models={len(models)} (default={default_id}) | accounts={len(CONF['accounts'])} | "
        f"machine={MACHINE_HASH[:12]}..."
    )
    srv = ThreadedHTTPServer((host, port), ProxyHandler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("shutting down")


if __name__ == "__main__":
    main()
