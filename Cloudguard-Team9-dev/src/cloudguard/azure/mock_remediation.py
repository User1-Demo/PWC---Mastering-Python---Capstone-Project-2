from cloudguard.schemas.azure_resource import AzureResource


def add_missing_tag(
    resource: AzureResource,
    tag_name: str,
    tag_value: str,
) -> tuple[AzureResource, bool]:
    # Idempotency: if the tag already exists, do nothing.
    existing_tags = {
        key.casefold()
        for key in resource.tags
    }

    if tag_name.casefold() in existing_tags:
        return resource, False

    updated_tags = resource.tags.copy()
    updated_tags[tag_name] = tag_value

    updated_resource = resource.model_copy(
        update={"tags": updated_tags}
    )

    return updated_resource, True