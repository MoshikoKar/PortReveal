"""closed-value CHECK constraints; pending-digest index on events

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-09 18:00:00.000000

Value sets are frozen here (not imported from app.models) so this revision keeps meaning the
same thing when the application's sets change later.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

EVENT_TYPES = (
    "device_discovered", "device_disappeared", "device_reappeared", "ip_changed", "port_opened",
    "port_closed", "service_detected", "service_changed", "version_changed", "tag_added",
    "tag_removed", "watch_match", "policy_violation",
)

# (table, column, allowed values, repair). Before a constraint is added, out-of-set rows are
# repaired: None -> set NULL (nullable column), a string -> set to that value, RAISE -> abort,
# because no value can be substituted without inventing history.
RAISE = object()
CLOSED_VALUES = (
    ("users", "role", ("admin", "viewer"), "viewer"),  # least privilege
    ("users", "source", ("local", "ldap"), "local"),
    ("networks", "zone", ("servers", "users", "iot", "dmz", "management", "guest", "lab"), None),
    ("devices", "status", ("active", "unknown", "not_detected"), "unknown"),
    ("device_tags", "source", ("rule", "manual", "suppressed"), "rule"),  # rule tags are recomputed
    ("device_profiles", "criticality", ("low", "medium", "high", "critical"), None),
    ("scans", "scan_type", ("discovery", "standard", "full"), RAISE),
    ("scans", "trigger", ("manual", "scheduled", "presence"), "manual"),
    ("scans", "status", ("queued", "running", "completed", "partial", "failed", "cancelled"), "failed"),
    ("events", "event_type", EVENT_TYPES, RAISE),
    ("events", "severity", ("high", "medium", "low", "info"), "info"),
)


def _in_list(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _repair(table: str, column: str, values: tuple[str, ...], repair) -> None:
    outside = f'"{column}" IS NOT NULL AND "{column}" NOT IN ({_in_list(values)})'
    if repair is RAISE:
        bad = op.get_bind().execute(sa.text(f"SELECT COUNT(*) FROM {table} WHERE {outside}")).scalar()
        if bad:
            raise RuntimeError(
                f"{bad} row(s) in {table}.{column} hold values outside {values}; "
                "correct or delete them, then run the migration again"
            )
        return
    new = "NULL" if repair is None else f"'{repair}'"
    op.execute(f'UPDATE {table} SET "{column}" = {new} WHERE {outside}')


def upgrade() -> None:
    for table, column, values, repair in CLOSED_VALUES:
        _repair(table, column, values, repair)
    # One batch per table: on SQLite each batch rebuilds the table once (foreign keys are off
    # during migrations, so the rebuild does not cascade); on PostgreSQL it is a plain ALTER.
    by_table: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
    for table, column, values, _repair_value in CLOSED_VALUES:
        by_table.setdefault(table, []).append((column, values))
    for table, columns in by_table.items():
        with op.batch_alter_table(table, schema=None) as batch_op:
            for column, values in columns:
                batch_op.create_check_constraint(f"ck_{table}_{column}", f'"{column}" IN ({_in_list(values)})')
            if table == "events":
                batch_op.create_index("ix_events_pending", ["notify", "notified_at"], unique=False)


def downgrade() -> None:
    by_table: dict[str, list[str]] = {}
    for table, column, _values, _repair_value in CLOSED_VALUES:
        by_table.setdefault(table, []).append(column)
    for table, columns in by_table.items():
        with op.batch_alter_table(table, schema=None) as batch_op:
            if table == "events":
                batch_op.drop_index("ix_events_pending")
            for column in columns:
                batch_op.drop_constraint(f"ck_{table}_{column}", type_="check")
