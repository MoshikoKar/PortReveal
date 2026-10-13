"""Local LLM identity must come from response content, never from the port alone."""
from __future__ import annotations

from app.core.web_capture.identify_ai import identify_local_ai
from app.scanner.known_ports import AI_LLM_TCP_PORTS, merge_port_scope
from app.scanner.nmap_scanner import build_fixed_port_args, build_port_args
from app.scanner.types import PortProfile


def test_known_ports_include_documented_defaults():
    ports = set(AI_LLM_TCP_PORTS)
    assert {11434, 1234, 1337, 4891, 9997, 3001, 4000}.issubset(ports)
    assert 8081 not in ports  # not a documented LocalAI default
    assert merge_port_scope("80,443", (11434, 1234)) == "80,443,1234,11434"


def test_ollama_from_banner_not_port():
    assert identify_local_ai(body="Ollama is running") == "Ollama"
    assert identify_local_ai(path="/", body="ok") is None
    assert identify_local_ai(path="/", title="Home") is None


def test_ollama_from_api_tags_shape():
    body = '{"models":[{"name":"llama3.2:latest","digest":"sha256:abc","modified_at":"2024-01-01T00:00:00Z","size":1}]}'
    assert identify_local_ai(path="/api/tags", content_type="application/json", body=body) == "Ollama"


def test_lm_studio_from_models_owned_by():
    body = '{"object":"list","data":[{"id":"llama-3.2","object":"model","owned_by":"organization_owner"}]}'
    assert identify_local_ai(path="/v1/models", content_type="application/json", body=body) == "LM Studio"


def test_openai_compatible_without_vendor_stamp():
    body = '{"object":"list","data":[{"id":"my-model","object":"model","owned_by":"user"}]}'
    assert identify_local_ai(path="/v1/models", content_type="application/json", body=body) == (
        "OpenAI-compatible LLM API"
    )


def test_title_identifies_open_webui():
    assert identify_local_ai(title="Open WebUI", body="<html></html>") == "Open WebUI"


# Scan-command integrity invariant; the threat model and full index live in test_nmap_command_integrity.py.
def test_fixed_port_args_include_ai_candidates():
    profile = PortProfile(full=False, top_ports=3000)
    std = build_port_args(True, profile)
    assert "--top-ports" in std
    fixed = build_fixed_port_args(True, profile, AI_LLM_TCP_PORTS)
    assert "-p" in fixed
    spec = fixed[fixed.index("-p") + 1]
    assert "11434" in spec and "1234" in spec
