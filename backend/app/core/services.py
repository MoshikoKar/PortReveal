"""The service name the UI may show for a port: only what nmap actually confirmed.

nmap's `method="table"` name is a lookup of the port number in nmap-services (port 6668 ->
"irc"), not something the device said, so it is shown as "unknown". The stored row keeps the
raw value; only presentation changes. "tcpwrapped" means the port accepted the connection and
closed it without sending anything.
"""
from __future__ import annotations

from sqlalchemy import case, func, literal_column

from ..models import DevicePort

UNKNOWN = "unknown"
NO_RESPONSE = "open, no response"


def shown_service(service: str | None, method: str | None) -> str:
    if not service or method != "probed":
        return UNKNOWN
    if service == "tcpwrapped":
        return NO_RESPONSE
    return service


def shown_service_sql():
    """SQL twin of shown_service(). literal_column keeps SELECT and GROUP BY identical on PostgreSQL."""
    return case(
        (func.coalesce(DevicePort.method, literal_column("''")) != literal_column("'probed'"),
         literal_column(f"'{UNKNOWN}'")),
        (DevicePort.service == literal_column("'tcpwrapped'"), literal_column(f"'{NO_RESPONSE}'")),
        else_=func.coalesce(DevicePort.service, literal_column(f"'{UNKNOWN}'")),
    )
