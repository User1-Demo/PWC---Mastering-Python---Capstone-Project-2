from pydantic import BaseModel, Field


class AzureSecurityRule(BaseModel):
    name: str
    direction: str
    access: str
    protocol: str
    source_address_prefix: str
    destination_port_range: str
    priority: int


class AzureResource(BaseModel):
    id: str
    name: str
    type: str
    location: str
    tags: dict[str, str] = Field(default_factory=dict)
    security_rules: list[AzureSecurityRule] = Field(default_factory=list)