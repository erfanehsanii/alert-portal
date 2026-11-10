from unittest.mock import patch

import pytest

from app.services.promql_templates import (
    CPU_TARGETS_QUERY,
    FILESYSTEMS_QUERY,
    MEMORY_AVAILABLE_TARGETS_QUERY,
    MEMORY_TOTAL_TARGETS_QUERY,
    PrometheusTemplateOptionsUnavailable,
    get_promql_template_options,
)
from app.services.promql_validation import PrometheusValidationUnavailable


def vector_item(**labels):
    return {"metric": labels, "value": [1, "1"]}


def test_template_options_intersect_metrics_and_exclude_pseudo_filesystems():
    cpu_targets = [
        vector_item(job="node-exporter", instance="node-a:9100"),
        vector_item(job="node-exporter", instance="node-b:9100"),
        vector_item(job="k8s-cluster-haproxy", instance="proxy-a:9100"),
    ]
    memory_available = [
        vector_item(job="node-exporter", instance="node-a:9100"),
        vector_item(job="node-exporter", instance="node-b:9100"),
        vector_item(job="k8s-cluster-haproxy", instance="proxy-a:9100"),
    ]
    memory_total = [
        vector_item(job="node-exporter", instance="node-a:9100"),
        vector_item(job="k8s-cluster-haproxy", instance="proxy-a:9100"),
    ]
    filesystems = [
        vector_item(
            job="node-exporter", instance="node-a:9100", device="/dev/sda1",
            mountpoint="/", fstype="ext4",
        ),
        vector_item(
            job="node-exporter", instance="node-a:9100", device="tmpfs",
            mountpoint="/run", fstype="tmpfs",
        ),
        vector_item(
            job="node-exporter", instance="node-b:9100", device="/dev/sdb1",
            mountpoint="/data", fstype="xfs",
        ),
        vector_item(
            job="k8s-cluster-haproxy", instance="proxy-a:9100", device="/dev/vda1",
            mountpoint="/", fstype="ext4",
        ),
        vector_item(
            job="node-exporter", instance="node-a:9100", device="/dev/bad\nvalue",
            mountpoint="/bad", fstype="ext4",
        ),
    ]

    with patch(
        "app.services.promql_templates.query_prometheus_vector",
        side_effect=[cpu_targets, memory_available, memory_total, filesystems],
    ) as query:
        options = get_promql_template_options()

    assert options["targets"] == [
        {"job": "k8s-cluster-haproxy", "instance": "proxy-a:9100"},
        {"job": "node-exporter", "instance": "node-a:9100"},
    ]
    assert options["filesystems"] == [
        {
            "job": "k8s-cluster-haproxy", "instance": "proxy-a:9100",
            "mountpoint": "/", "device": "/dev/vda1", "fstype": "ext4",
        },
        {
            "job": "node-exporter", "instance": "node-a:9100",
            "mountpoint": "/", "device": "/dev/sda1", "fstype": "ext4",
        },
    ]
    assert options["target_count"] == 2
    assert options["filesystem_count"] == 2
    assert options["result_limit"] == 1000
    assert query.call_count == 4
    assert query.call_args_list[0].args[0] == CPU_TARGETS_QUERY
    assert query.call_args_list[1].args[0] == MEMORY_AVAILABLE_TARGETS_QUERY
    assert query.call_args_list[2].args[0] == MEMORY_TOTAL_TARGETS_QUERY
    assert query.call_args_list[3].args[0] == FILESYSTEMS_QUERY
    assert "tmpfs|overlay" in FILESYSTEMS_QUERY


def test_template_options_fail_closed_when_prometheus_is_unavailable():
    with patch(
        "app.services.promql_templates.query_prometheus_vector",
        side_effect=PrometheusValidationUnavailable("internal detail"),
    ):
        with pytest.raises(PrometheusTemplateOptionsUnavailable) as exc:
            get_promql_template_options()
    assert "target options could not be loaded" in str(exc.value)
    assert "internal detail" not in str(exc.value)


def test_invalid_or_incomplete_filesystem_labels_are_skipped():
    target = vector_item(job="node-exporter", instance="node-a:9100")
    incomplete_fs = vector_item(
        job="node-exporter", instance="node-a:9100", mountpoint="/",
        fstype="ext4",
    )
    with patch(
        "app.services.promql_templates.query_prometheus_vector",
        side_effect=[[target], [target], [target], [incomplete_fs]],
    ):
        options = get_promql_template_options()
    assert options["targets"] == [{"job": "node-exporter", "instance": "node-a:9100"}]
    assert options["filesystems"] == []
