from types import SimpleNamespace

import pytest
from kubernetes.config.config_exception import ConfigException

from app.config import get_settings
from app.services.dispatcher import DispatchError, dispatch_remediation, dispatch_scan


def test_kubernetes_dispatch_builds_worker_jobs_with_separate_identities(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "execution_mode", "kubernetes")
    monkeypatch.setattr(settings, "worker_image", "registry.local/cloudguard:test")
    captured = []
    monkeypatch.setattr("kubernetes.config.load_incluster_config", lambda: None)
    monkeypatch.setattr(
        "kubernetes.client.BatchV1Api",
        lambda: SimpleNamespace(
            create_namespaced_job=lambda namespace, body: captured.append((namespace, body))
        ),
    )

    dispatch_scan(12)
    dispatch_remediation(34)

    assert [namespace for namespace, _ in captured] == ["cloudguard", "cloudguard"]
    scan_job = captured[0][1]
    scan_pod = scan_job.spec.template
    assert scan_pod.spec.service_account_name == "cloudguard-scan-worker"
    assert scan_pod.metadata.labels["azure.workload.identity/use"] == "true"
    assert scan_pod.spec.containers[0].args == ["scan", "12"]
    assert scan_pod.spec.containers[0].image == "registry.local/cloudguard:test"
    remediation_job = captured[1][1]
    assert remediation_job.spec.template.spec.service_account_name == "cloudguard-remediation-worker"
    assert remediation_job.spec.template.spec.containers[0].args == ["remediate", "34"]


def test_kubernetes_configuration_failure_is_reported(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "execution_mode", "kubernetes")

    def fail_config():
        raise ConfigException("not running in a cluster")

    monkeypatch.setattr("kubernetes.config.load_incluster_config", fail_config)
    with pytest.raises(DispatchError, match="Kubernetes worker dispatch failed"):
        dispatch_scan(99)
