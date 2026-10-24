from dataclasses import dataclass

from cloudguard.schemas.azure_resource import AzureResource


@dataclass(frozen=True)
class TagViolation:
    resource_id: str
    resource_name: str
    resource_type: str
    missing_tag: str
    message: str


def evaluate_required_tag(
    resource: AzureResource,
    required_tag: str,
) -> TagViolation | None:
    normalized_tags = {
        key.casefold(): value
        for key, value in resource.tags.items()
    }

    if required_tag.casefold() in normalized_tags:
        return None

    return TagViolation(
        resource_id=resource.id,
        resource_name=resource.name,
        resource_type=resource.type,
        missing_tag=required_tag,
        message=(
            f"Resource '{resource.name}' is missing "
            f"required tag '{required_tag}'"
        ),
    )