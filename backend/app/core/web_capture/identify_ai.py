"""Passive identification of local / self-hosted AI and LLM API services.

Identity comes only from HTTP response evidence (title, body text, JSON shape,
Server header). Port numbers are never used to name a product - the same port
can host anything.
"""
from __future__ import annotations

import json
import re
from typing import Any

# Strong text/title/server matches (product name only when the string is distinctive).
_TEXT_SIGNATURES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^\s*Ollama is running\s*$", re.I | re.M), "Ollama"),
    (re.compile(r"<title[^>]*>\s*Ollama\s*</title>", re.I), "Ollama"),
    (re.compile(r"<title[^>]*>[^<]*\bLM Studio\b[^<]*</title>", re.I), "LM Studio"),
    (re.compile(r"\bLM Studio\b", re.I), "LM Studio"),
    (re.compile(r"<title[^>]*>[^<]*\bLocalAI\b[^<]*</title>", re.I), "LocalAI"),
    (re.compile(r"\bWelcome to LocalAI\b|\bLocalAI\b.*OpenAI", re.I), "LocalAI"),
    (re.compile(r"<title[^>]*>[^<]*\bJan\b[^<]*</title>|\bWelcome to Jan\b|\bJan\.ai\b", re.I), "Jan"),
    (re.compile(r"\bGPT4All\b", re.I), "GPT4All"),
    (re.compile(r"\bOpen WebUI\b", re.I), "Open WebUI"),
    (re.compile(r"\btext-generation-webui\b|\boobabooga\b", re.I), "text-generation-webui"),
    (re.compile(r"\bKoboldCpp\b|\bKoboldAI\b", re.I), "KoboldCPP"),
    (re.compile(r"\bXinference\b", re.I), "Xinference"),
    (re.compile(r"\bvLLM\b", re.I), "vLLM"),
    (re.compile(r"\bLiteLLM\b", re.I), "LiteLLM"),
    (re.compile(r"\bAnythingLLM\b", re.I), "AnythingLLM"),
    (re.compile(r"\bllama\.cpp\b|\bllama-server\b", re.I), "llama.cpp"),
    (re.compile(r"\bTabbyAPI\b", re.I), "TabbyAPI"),
    (re.compile(r"\bSillyTavern\b", re.I), "SillyTavern"),
    (re.compile(r"\bAphrodite\b", re.I), "Aphrodite"),
    (re.compile(r"\bSGLang\b", re.I), "SGLang"),
    (re.compile(r"\bMsty\b", re.I), "Msty"),
)
GENERIC_LLM_API = "OpenAI-compatible LLM API"
# Every product name this module can write into DevicePort.product
AI_PRODUCTS = frozenset({name for _, name in _TEXT_SIGNATURES} | {GENERIC_LLM_API})


def _parse_json(text: str | None) -> Any | None:
    if not text:
        return None
    s = text.strip()
    if not s or s[0] not in "{[":
        return None
    try:
        return json.loads(s[:200_000])
    except (json.JSONDecodeError, ValueError):
        return None


def _model_rows(data: dict) -> list[dict]:
    rows = data.get("data")
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


def identify_from_openai_models_json(data: Any) -> str | None:
    """OpenAI-compatible GET /v1/models - name a vendor only from owned_by / id evidence."""
    if not isinstance(data, dict):
        return None
    rows = _model_rows(data)
    if data.get("object") not in (None, "list") and not rows:
        return None
    if not rows and data.get("object") != "list":
        return None

    owned = " ".join(str(r.get("owned_by") or "") for r in rows).lower()
    ids = " ".join(str(r.get("id") or "") for r in rows).lower()
    blob = f"{owned} {ids}"

    if "lmstudio" in blob or "lm-studio" in blob or "lm studio" in blob:
        return "LM Studio"
    # LM Studio commonly stamps owned_by as organization_owner
    if "organization_owner" in owned and rows:
        return "LM Studio"
    if "localai" in blob:
        return "LocalAI"
    if "ollama" in blob:
        return "Ollama"
    if "vllm" in blob:
        return "vLLM"
    if "litellm" in blob:
        return "LiteLLM"
    if "xinference" in blob:
        return "Xinference"
    # Generic OpenAI-compatible list with model ids - content proves an LLM API, not a port.
    if data.get("object") == "list" and rows and any(r.get("id") for r in rows):
        return GENERIC_LLM_API
    return None


def identify_from_ollama_tags_json(data: Any) -> str | None:
    """Ollama GET /api/tags → { models: [ { name, model?, digest?, modified_at?, size? } ] }."""
    if not isinstance(data, dict):
        return None
    models = data.get("models")
    if not isinstance(models, list):
        return None
    if not models:
        # Empty catalog is still Ollama's tags document when the key is present
        # and no conflicting OpenAI "object":"list" wrapper is used.
        if "object" in data and data.get("object") == "list":
            return None
        return "Ollama"
    sample = next((m for m in models if isinstance(m, dict)), None)
    if sample is None:
        return None
    # Ollama model objects expose digest / modified_at / size alongside name
    ollama_keys = ("digest", "modified_at", "details", "size")
    if any(k in sample for k in ollama_keys) and ("name" in sample or "model" in sample):
        return "Ollama"
    if set(sample.keys()) >= {"name"} and "id" not in sample and "object" not in data:
        return "Ollama"
    return None


def identify_from_ollama_version_json(data: Any) -> str | None:
    """Ollama GET /api/version → { version: "x.y.z" } (only when path says /api/version)."""
    if not isinstance(data, dict):
        return None
    ver = data.get("version")
    if isinstance(ver, str) and ver.strip() and set(data.keys()) <= {"version"}:
        return "Ollama"
    return None


def identify_local_ai(
    *,
    path: str | None = None,
    title: str | None = None,
    server_header: str | None = None,
    content_type: str | None = None,
    body: str | None = None,
) -> str | None:
    """Return a product name only when response content clearly identifies it."""
    path_l = (path or "").lower()
    ctype = (content_type or "").lower()
    title_s = title or ""
    server_s = server_header or ""
    body_s = (body or "")[:8000]
    blob = f"{title_s}\n{server_s}\n{body_s}"

    data = _parse_json(body) if ("json" in ctype or body_s.lstrip()[:1] in "{[") else None
    if data is not None:
        if path_l.rstrip("/").endswith("/api/tags"):
            hit = identify_from_ollama_tags_json(data)
            if hit:
                return hit
        if path_l.rstrip("/").endswith("/api/version"):
            hit = identify_from_ollama_version_json(data)
            if hit:
                return hit
        if "models" in path_l or "/v1/" in path_l:
            hit = identify_from_openai_models_json(data)
            if hit:
                return hit
        hit = identify_from_ollama_tags_json(data) or identify_from_openai_models_json(data)
        if hit:
            return hit

    # Plain-text Ollama banner (exact), then broader title/body signatures
    if re.search(r"^\s*Ollama is running\s*$", body_s, re.I | re.M):
        return "Ollama"
    for rx, name in _TEXT_SIGNATURES:
        if rx.search(blob):
            return name
    return None
