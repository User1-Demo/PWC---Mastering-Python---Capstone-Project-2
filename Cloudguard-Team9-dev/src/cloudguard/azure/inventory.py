from abc import ABC, abstractmethod

from cloudguard.schemas.azure_resource import AzureResource


class InventoryProvider(ABC):

    @abstractmethod
    def list_resources(self) -> list[AzureResource]:
        """Return resources that CloudGuard should evaluate."""
        raise NotImplementedError