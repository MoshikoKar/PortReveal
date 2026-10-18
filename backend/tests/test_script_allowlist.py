"""SCRIPT_ALLOWLIST trigger rules (spec 8.4.1-8.4.2): only the port/service/tunnel that justifies it."""
from __future__ import annotations

from app.scanner.script_allowlist import SCRIPT_NAMES, scripts_for_port


def test_smb_scripts_only_on_445():
    names = scripts_for_port(445, "microsoft-ds", None)
    assert "smb-vuln-ms17-010" in names
    assert "smb-os-discovery" in names
    assert scripts_for_port(446, "microsoft-ds", None) == []  # wrong port, same service name coincidence
    assert scripts_for_port(80, "http", None) == [] or "smb-vuln-ms17-010" not in scripts_for_port(80, "http", None)


def test_tls_scripts_trigger_on_tunnel_or_service_name():
    assert "ssl-heartbleed" in scripts_for_port(8443, "unknown", "ssl")
    assert "ssl-heartbleed" in scripts_for_port(443, "https", None)
    assert "ssl-heartbleed" not in scripts_for_port(80, "http", None)


def test_http_ntlm_only_on_http_like_services():
    assert "http-ntlm-info" in scripts_for_port(80, "http", None)
    assert "http-ntlm-info" in scripts_for_port(8080, "http-proxy", None)
    assert "http-ntlm-info" not in scripts_for_port(22, "ssh", None)


def test_ssh_scripts_trigger_on_port_or_service():
    assert "ssh2-enum-algos" in scripts_for_port(22, "ssh", None)
    assert "ssh2-enum-algos" in scripts_for_port(2222, "ssh", None)  # non-standard port, service name matches
    assert "ssh2-enum-algos" not in scripts_for_port(2222, "unknown", None)


def test_never_suggests_a_name_outside_the_allowlist():
    for port, service, tunnel in [(445, "microsoft-ds", None), (443, "https", None), (22, "ssh", None),
                                  (3389, "ms-wbt-server", None), (21, "ftp", None)]:
        assert set(scripts_for_port(port, service, tunnel)) <= SCRIPT_NAMES


def test_no_script_runs_on_an_unrelated_port():
    assert scripts_for_port(12345, "unknown", None) == []
