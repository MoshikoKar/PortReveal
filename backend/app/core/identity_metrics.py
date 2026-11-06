"""Synthetic identity trade-off metrics with explicit ground truth (issue #39 item 8).

This module never talks to a live network. Callers supply labeled host/device scenarios;
``evaluate`` counts false-new devices and false merges against that ground truth.

Production deployment rates are *not* produced here - those need a real inventory sample
and remain an unmet acceptance item until measured outside the cloud agent.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..scanner.types import HostObservation
from .identity import match_hosts_detailed


@dataclass(frozen=True)
class LabeledHost:
    """One observation plus the device id it *should* match (None = correctly new)."""

    host: HostObservation
    expected_device_id: int | None


@dataclass(frozen=True)
class Metrics:
    hosts: int
    true_match: int
    true_new: int
    false_new: int  # expected an existing device, got None
    false_merge: int  # matched the wrong device, or matched when expected new
    correct: int

    @property
    def false_new_rate(self) -> float:
        return self.false_new / self.hosts if self.hosts else 0.0

    @property
    def false_merge_rate(self) -> float:
        return self.false_merge / self.hosts if self.hosts else 0.0


def evaluate(
    labeled: list[LabeledHost],
    devices: list[Any],
    network_of: Callable[[str], Any] | None = None,
) -> Metrics:
    """Score ``match_hosts_detailed`` against ground-truth labels (synthetic only)."""
    result = match_hosts_detailed([row.host for row in labeled], devices, network_of)
    true_match = true_new = false_new = false_merge = 0
    for row in labeled:
        got = result.get(row.host.ip)
        got_id = got[0].id if got else None
        if row.expected_device_id is None:
            if got_id is None:
                true_new += 1
            else:
                false_merge += 1
        elif got_id == row.expected_device_id:
            true_match += 1
        elif got_id is None:
            false_new += 1
        else:
            false_merge += 1
    correct = true_match + true_new
    return Metrics(
        hosts=len(labeled),
        true_match=true_match,
        true_new=true_new,
        false_new=false_new,
        false_merge=false_merge,
        correct=correct,
    )
