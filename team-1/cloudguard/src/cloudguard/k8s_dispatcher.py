"""
Dispatches scan/remediation work as Kubernetes Jobs. Falls back to in-process
execution (same call signature) when not running inside/against a cluster —
useful for local dev & CI.
"""
import uuid
import logging
from .config import get_settings

log = logging.getLogger("k8s_dispatcher")
settings = get_settings()


def _k8s_batch_client():
    from kubernetes import client, config as kconfig
    if settings.k8s_in_cluster:
        kconfig.load_incluster_config()
    else:
        kconfig.load_kube_config()
    return client.BatchV1Api()


def dispatch_scan_job(scan_id: str) -> str:
    job_name = f"scan-{scan_id[:8]}-{uuid.uuid4().hex[:4]}"
    try:
        from kubernetes import client
        batch = _k8s_batch_client()
        container = client.V1Container(
            name="scan-worker",
            image=settings.scan_worker_image,
            args=["python", "-m", "cloudguard.workers.scan_worker", "--scan-id", scan_id],
            env_from=[client.V1EnvFromSource(
                secret_ref=client.V1SecretEnvSource(name="cloudguard-secrets"))],
        )
        template = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(labels={"app": "cloudguard-scan"}),
            spec=client.V1PodSpec(containers=[container], restart_policy="Never"),
        )
        spec = client.V1JobSpec(template=template, backoff_limit=2, ttl_seconds_after_finished=3600)
        job = client.V1Job(
            metadata=client.V1ObjectMeta(name=job_name, namespace=settings.k8s_namespace),
            spec=spec,
        )
        batch.create_namespaced_job(namespace=settings.k8s_namespace, body=job)
        log.info("Dispatched scan job %s", job_name)
    except Exception as e:
        log.warning("K8s dispatch unavailable (%s) — running scan in-process instead", e)
        from .workers.scan_worker import run_scan
        run_scan(scan_id)
    return job_name


def dispatch_remediation_job(finding_id: str, actor: str, approved: bool) -> str:
    job_name = f"remediate-{finding_id[:8]}-{uuid.uuid4().hex[:4]}"
    try:
        from kubernetes import client
        batch = _k8s_batch_client()
        args = ["python", "-m", "cloudguard.workers.remediation_worker",
                "--finding-id", finding_id, "--actor", actor]
        if approved:
            args.append("--approved")
        container = client.V1Container(
            name="remediation-worker", image=settings.remediation_worker_image, args=args,
            env_from=[client.V1EnvFromSource(
                secret_ref=client.V1SecretEnvSource(name="cloudguard-secrets"))],
        )
        template = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(labels={"app": "cloudguard-remediation"}),
            spec=client.V1PodSpec(containers=[container], restart_policy="Never"),
        )
        spec = client.V1JobSpec(template=template, backoff_limit=1, ttl_seconds_after_finished=3600)
        job = client.V1Job(
            metadata=client.V1ObjectMeta(name=job_name, namespace=settings.k8s_namespace), spec=spec)
        batch.create_namespaced_job(namespace=settings.k8s_namespace, body=job)
    except Exception as e:
        log.warning("K8s dispatch unavailable (%s) — running remediation in-process instead", e)
        from .workers.remediation_worker import run_remediation
        run_remediation(finding_id, actor, approved)
    return job_name