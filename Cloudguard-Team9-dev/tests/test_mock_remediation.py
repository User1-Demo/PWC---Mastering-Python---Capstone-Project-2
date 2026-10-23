from cloudguard.azure.mock_remediation import add_missing_tag
from cloudguard.schemas.azure_resource import AzureResource


def test_add_missing_tag() -> None:
    resource = AzureResource(
        id="/resources/api-server-01",
        name="api-server-01",
        type="Microsoft.Compute/virtualMachines",
        location="centralindia",
        tags={
            "Owner": "application-team",
        },
    )

    updated_resource, changed = add_missing_tag(
        resource=resource,
        tag_name="Environment",
        tag_value="dev",
    )

    assert changed is True
    assert updated_resource.tags["Environment"] == "dev"


def test_remediation_is_idempotent() -> None:
    resource = AzureResource(
        id="/resources/web-server-01",
        name="web-server-01",
        type="Microsoft.Compute/virtualMachines",
        location="centralindia",
        tags={
            "Environment": "dev",
        },
    )

    updated_resource, changed = add_missing_tag(
        resource=resource,
        tag_name="Environment",
        tag_value="dev",
    )

    assert changed is False
    assert updated_resource == resource


def test_existing_tag_is_case_insensitive() -> None:
    resource = AzureResource(
        id="/resources/web-server-01",
        name="web-server-01",
        type="Microsoft.Compute/virtualMachines",
        location="centralindia",
        tags={
            "environment": "dev",
        },
    )

    updated_resource, changed = add_missing_tag(
        resource=resource,
        tag_name="Environment",
        tag_value="dev",
    )

    assert changed is False
    assert updated_resource == resource