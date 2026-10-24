import json
from pathlib import Path

from cloudguard.azure.inventory import InventoryProvider
from cloudguard.schemas.azure_resource import AzureResource

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_FIXTURE_PATH = (
    PROJECT_ROOT / "tests" / "fixtures" / "azure_resources.json"
)


def load_mock_resources(
    fixture_path: Path = DEFAULT_FIXTURE_PATH,
) -> list[AzureResource]:
    with fixture_path.open(encoding="utf-8") as fixture_file:
        resource_data = json.load(fixture_file)

    return [
        AzureResource.model_validate(resource)
        for resource in resource_data
    ]

class MockInventoryProvider(InventoryProvider):

    def list_resources(self) -> list[AzureResource]:
        return load_mock_resources()