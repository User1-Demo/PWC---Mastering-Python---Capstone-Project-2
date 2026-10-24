from functools import lru_cache

from app.config import get_settings
from app.providers.azure import AzureProvider
from app.providers.mock import MockAzureProvider


@lru_cache
def get_provider():
    if get_settings().azure_provider == "azure":
        return AzureProvider()
    return MockAzureProvider()

