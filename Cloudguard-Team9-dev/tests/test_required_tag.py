from cloudguard.azure.mock_inventory import load_mock_resources
from cloudguard.policies.required_tag import evaluate_required_tag
from cloudguard.schemas.azure_resource import AzureResource


def test_compliant_resource_returns_no_violation() -> None:
    resource = AzureResource(
        id="/resources/web-server-01",
        name="web-server-01",
        type="Microsoft.Compute/virtualMachines",
        location="centralindia",
        tags={
            "Environment": "dev",
            "Owner": "cloud-team",
        },
    )

    violation = evaluate_required_tag(
        resource=resource,
        required_tag="Environment",
    )

    assert violation is None


def test_missing_tag_returns_violation() -> None:
    resource = AzureResource(
        id="/resources/api-server-01",
        name="api-server-01",
        type="Microsoft.Compute/virtualMachines",
        location="centralindia",
        tags={
            "Owner": "application-team",
        },
    )

    violation = evaluate_required_tag(
        resource=resource,
        required_tag="Environment",
    )

    assert violation is not None
    assert violation.resource_id == "/resources/api-server-01"
    assert violation.resource_name == "api-server-01"
    assert violation.missing_tag == "Environment"
    assert violation.message == (
        "Resource 'api-server-01' is missing "
        "required tag 'Environment'"
    )


def test_tag_name_comparison_is_case_insensitive() -> None:
    resource = AzureResource(
        id="/resources/storage-account",
        name="storage-account",
        type="Microsoft.Storage/storageAccounts",
        location="centralindia",
        tags={
            "environment": "dev",
        },
    )

    violation = evaluate_required_tag(
        resource=resource,
        required_tag="Environment",
    )

    assert violation is None

def test_mock_inventory_has_two_tag_violations() -> None:
    resources = load_mock_resources()

    violations = [
        violation
        for resource in resources
        if (
            violation := evaluate_required_tag(
                resource=resource,
                required_tag="Environment",
            )
        )
        is not None
    ]

    assert len(violations) == 2

    violating_resource_names = {
        violation.resource_name
        for violation in violations
    }

    assert violating_resource_names == {
        "api-server-01",
        "cloudguarddevstorage",
    }