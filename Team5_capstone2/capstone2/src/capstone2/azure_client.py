from dataclasses import dataclass
from capstone2.config import get_settings

@dataclass
class Resource: id:str; name:str; type:str; tags:dict; properties:dict
class AzureInventoryClient:
    def list_resources(self, subscription_id:str)->list[Resource]:
        if get_settings().azure_mode=="mock":
            return [
              Resource(f"/subscriptions/{subscription_id}/resourceGroups/demo/providers/Microsoft.Compute/virtualMachines/vm1","vm1","Microsoft.Compute/virtualMachines",{"environment":"dev"},{}),
              Resource(f"/subscriptions/{subscription_id}/resourceGroups/demo/providers/Microsoft.Network/networkSecurityGroups/nsg1","nsg1","Microsoft.Network/networkSecurityGroups",{"owner":"cloud"},{"security_rules":[{"name":"AllowSSH","source":"*","port":22,"access":"Allow"}]})]
        return self._live(subscription_id)
    def _live(self,subscription_id):
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resource import ResourceManagementClient
        client=ResourceManagementClient(DefaultAzureCredential(),subscription_id)
        return [Resource(r.id,r.name,r.type,r.tags or {},dict(r.properties or {})) for r in client.resources.list()]
