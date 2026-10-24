from fastapi import BackgroundTasks

from app.config import get_settings


class DispatchError(RuntimeError):
    """A worker could not be scheduled by the configured execution backend."""


def dispatch_scan(scan_id: int, background_tasks: BackgroundTasks | None = None) -> None:
    if get_settings().execution_mode == "kubernetes":
        _dispatch_kubernetes_job("scan", scan_id)
    elif background_tasks is not None:
        from app.services.scans import execute_scan

        background_tasks.add_task(execute_scan, scan_id)
    else:
        from app.services.scans import execute_scan

        execute_scan(scan_id)


def dispatch_remediation(action_id: int, background_tasks: BackgroundTasks | None = None) -> None:
    if get_settings().execution_mode == "kubernetes":
        _dispatch_kubernetes_job("remediate", action_id)
    elif background_tasks is not None:
        from app.services.remediation import execute_remediation

        background_tasks.add_task(execute_remediation, action_id)
    else:
        from app.services.remediation import execute_remediation

        execute_remediation(action_id)


def _dispatch_kubernetes_job(kind: str, object_id: int) -> None:
    from kubernetes import client, config
    from kubernetes.client.exceptions import ApiException
    from kubernetes.config.config_exception import ConfigException

    settings = get_settings()
    try:
        config.load_incluster_config()
        batch = client.BatchV1Api()
        name = f"cloudguard-{kind}-{object_id}"
        service_account = (
            settings.kubernetes_remediation_service_account
            if kind == "remediate"
            else settings.kubernetes_scan_service_account
        )
        job = client.V1Job(
            metadata=client.V1ObjectMeta(name=name, namespace=settings.kubernetes_namespace),
            spec=client.V1JobSpec(
                backoff_limit=0,
                active_deadline_seconds=900,
                ttl_seconds_after_finished=3600,
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        labels={"azure.workload.identity/use": "true"}
                    ),
                    spec=client.V1PodSpec(
                        restart_policy="Never",
                        service_account_name=service_account,
                        containers=[
                            client.V1Container(
                                name="worker",
                                image=settings.worker_image,
                                image_pull_policy="IfNotPresent",
                                command=["python", "-m", "app.worker"],
                                args=[kind, str(object_id)],
                                env_from=[
                                    client.V1EnvFromSource(
                                        secret_ref=client.V1SecretEnvSource(
                                            name=settings.kubernetes_secret_name
                                        )
                                    )
                                ],
                            )
                        ],
                    )
                ),
            ),
        )
        batch.create_namespaced_job(namespace=settings.kubernetes_namespace, body=job)
    except (ApiException, ConfigException, OSError) as error:
        raise DispatchError(f"Kubernetes worker dispatch failed: {error}") from error

