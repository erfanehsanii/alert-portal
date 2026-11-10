"""Dynamic, bounded target options for built-in PromQL templates."""

from __future__ import annotations

import re
from typing import Any

from app.services.promql_validation import (
    PrometheusValidationUnavailable,
    query_prometheus_vector,
)


RESULT_LIMIT = 1000
PERSISTENT_FILESYSTEM_FILTER = (
    r"tmpfs|overlay|squashfs|ramfs|devtmpfs|proc|sysfs|cgroup2?|pstore|"
    r"debugfs|tracefs|securityfs|bpf|configfs|efivarfs|autofs|nsfs|"
    r"hugetlbfs|mqueue|fusectl"
)
_NON_PERSISTENT_FSTYPE_RE = re.compile(PERSISTENT_FILESYSTEM_FILTER, re.IGNORECASE)

# Only server-authored PromQL is used here. Dynamic labels are selected from
# these results and later quoted as PromQL string literals in the browser.
CPU_TARGETS_QUERY = (
    'count by (job, instance) (node_cpu_seconds_total{mode="idle"})'
)
MEMORY_AVAILABLE_TARGETS_QUERY = (
    "count by (job, instance) (node_memory_MemAvailable_bytes)"
)
MEMORY_TOTAL_TARGETS_QUERY = (
    "count by (job, instance) (node_memory_MemTotal_bytes)"
)
FILESYSTEMS_QUERY = (
    'node_filesystem_size_bytes{fstype!~"'
    + PERSISTENT_FILESYSTEM_FILTER
    + '"} and on (job, instance, device, mountpoint, fstype) '
    'node_filesystem_avail_bytes{fstype!~"'
    + PERSISTENT_FILESYSTEM_FILTER
    + '"}'
)


class PrometheusTemplateOptionsUnavailable(RuntimeError):
    """Raised when Prometheus cannot provide current template target choices."""


def _labels(result: dict[str, Any]) -> dict[str, str]:
    metric = result.get("metric") if isinstance(result, dict) else None
    if not isinstance(metric, dict):
        return {}
    return {
        key: value
        for key, value in metric.items()
        if isinstance(key, str) and isinstance(value, str) and value
    }


def _target_pairs(results: list[dict[str, Any]]) -> set[tuple[str, str]]:
    targets = set()
    for result in results:
        labels = _labels(result)
        job = labels.get("job")
        instance = labels.get("instance")
        if job and instance and len(job) <= 256 and len(instance) <= 256:
            if not any(ord(char) < 32 or ord(char) == 127 for char in job + instance):
                targets.add((job, instance))
    return targets


def _query(expression: str) -> list[dict[str, Any]]:
    try:
        return query_prometheus_vector(expression, result_limit=RESULT_LIMIT)
    except PrometheusValidationUnavailable:
        raise PrometheusTemplateOptionsUnavailable(
            "Prometheus target options could not be loaded."
        ) from None


def get_promql_template_options() -> dict[str, Any]:
    """Return available CPU/memory targets and persistent filesystem selectors.

    Only target pairs with both CPU idle-time and memory available/total metrics
    are offered. Filesystem choices require both size and available-byte metrics
    and exclude pseudo-filesystems such as tmpfs and overlay mounts.
    """
    cpu_targets = _target_pairs(_query(CPU_TARGETS_QUERY))
    memory_available_targets = _target_pairs(_query(MEMORY_AVAILABLE_TARGETS_QUERY))
    memory_total_targets = _target_pairs(_query(MEMORY_TOTAL_TARGETS_QUERY))
    compatible_targets = cpu_targets & memory_available_targets & memory_total_targets

    targets = [
        {"job": job, "instance": instance}
        for job, instance in sorted(compatible_targets)
    ]

    filesystem_results = _query(FILESYSTEMS_QUERY)
    filesystem_pairs: set[tuple[str, str, str, str, str]] = set()
    for result in filesystem_results:
        labels = _labels(result)
        job = labels.get("job")
        instance = labels.get("instance")
        device = labels.get("device")
        mountpoint = labels.get("mountpoint")
        fstype = labels.get("fstype")
        if not all((job, instance, device, mountpoint, fstype)):
            continue
        if (job, instance) not in compatible_targets:
            continue
        if _NON_PERSISTENT_FSTYPE_RE.search(fstype):
            continue
        if any(
            len(value) > 512 or any(ord(char) < 32 or ord(char) == 127 for char in value)
            for value in (device, mountpoint, fstype)
        ):
            continue
        filesystem_pairs.add((job, instance, mountpoint, device, fstype))

    filesystems = [
        {
            "job": job,
            "instance": instance,
            "mountpoint": mountpoint,
            "device": device,
            "fstype": fstype,
        }
        for job, instance, mountpoint, device, fstype in sorted(filesystem_pairs)
    ]

    return {
        "targets": targets,
        "filesystems": filesystems,
        "target_count": len(targets),
        "filesystem_count": len(filesystems),
        "result_limit": RESULT_LIMIT,
    }
