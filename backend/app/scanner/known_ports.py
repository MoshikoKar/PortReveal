"""Extra TCP ports to include in standard scans (candidates only).

These are documented *default* listen ports for common local / self-hosted
AI and LLM stacks. They exist so nmap --top-ports does not miss them.

Ports are NOT identity: an open port here only means "worth scanning / probing".
Service names (Ollama, LM Studio, …) must come from response fingerprints
(title, body, JSON shape, Server header) in web capture — see
``app.core.web_capture.identify_ai``.
"""
from __future__ import annotations

from ..netutils import PortScope

# Documented defaults for local LLM APIs / UIs that often fall outside --top-ports.
# Keep comments tied to the usual product; do not treat the comment as proof at runtime.
AI_LLM_TCP_PORTS: tuple[int, ...] = (
    1234,   # LM Studio local server (lms server start --port 1234)
    1337,   # Jan desktop API
    2242,   # Aphrodite Engine
    3001,   # AnythingLLM (Docker -p 3001:3001)
    4000,   # LiteLLM proxy
    4891,   # GPT4All local API
    5001,   # KoboldCPP
    7860,   # Gradio (many local AI UIs, including text-generation-webui)
    9997,   # Xinference (xinference-local --port 9997)
    10000,  # Msty local server
    11434,  # Ollama (ollama serve)
    30000,  # SGLang
)

# Default listen ports of modern web-app dev servers and frameworks — the ones AI code
# assistants scaffold onto by default. Open here means "likely HTTP, worth scanning / probing",
# never a product label.
WEB_DEV_TCP_PORTS: tuple[int, ...] = (
    3000,   # Node / Next.js / Create React App / Rails / Grafana
    3030,   # Meteor
    3050,   # dev tooling / RethinkDB admin / Firebird
    4000,   # Phoenix / Jekyll (also LiteLLM, above)
    4200,   # Angular CLI
    4321,   # Astro
    5000,   # Flask / ASP.NET Core / Docker registry
    5173,   # Vite
    5174,   # Vite (second instance)
    5500,   # VS Code Live Server
    8000,   # Django / uvicorn / python -m http.server / FastAPI
    8080,   # common HTTP alternate / many proxied dev servers
    8081,   # common HTTP alternate
    8443,   # common HTTPS alternate
    8501,   # Streamlit
    8888,   # Jupyter
    9000,   # SonarQube / PHP-FPM / various dashboards
)

# Ports added to every standard scan on top of nmap --top-ports: local AI/LLM APIs plus
# web-app dev servers. De-duplicated and sorted.
STANDARD_EXTRA_TCP_PORTS: tuple[int, ...] = tuple(sorted(set(AI_LLM_TCP_PORTS) | set(WEB_DEV_TCP_PORTS)))

# Short list for host-discovery SYN/connect probes (keep discovery cheap): the AI API ports
# plus the handful of dev-server ports that most often identify a live app box.
AI_LLM_DISCOVERY_TCP_PORTS: tuple[int, ...] = (
    1234, 1337, 4891, 9997, 11434,  # AI/LLM APIs
    3000, 5000, 5173, 8000,         # web-app dev servers
)

# Ports that often speak HTTP even when nmap leaves service empty/unknown.
# Again: candidates for web capture only — not product labels.
AI_LLM_WEB_PORTS: frozenset[int] = frozenset(AI_LLM_TCP_PORTS) | frozenset(WEB_DEV_TCP_PORTS)


def merge_port_scope(base: str | None, extra_ports: tuple[int, ...] | list[int]) -> str | None:
    """Append any extra TCP ports not already covered by an nmap services= scope."""
    extras = sorted({int(p) for p in extra_ports if 1 <= int(p) <= 65535})
    if not extras:
        return base
    if not base:
        return PortScope.from_ports(extras)
    scope = PortScope(base)
    missing = [p for p in extras if p not in scope]
    if not missing:
        return base
    return f"{base},{PortScope.from_ports(missing)}"


def mock_standard_scope(base: str = "1-10000") -> str:
    """Mock standard scans cover the usual low ports plus AI/LLM and web-dev candidate ports."""
    return merge_port_scope(base, STANDARD_EXTRA_TCP_PORTS) or base
