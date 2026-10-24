from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

class ORM(BaseModel): model_config=ConfigDict(from_attributes=True)
class LoginRequest(BaseModel): username:str; password:str
class Token(BaseModel): access_token:str; token_type:str="bearer"
class UserCreate(BaseModel): username:str; password:str=Field(min_length=8); role:str
class SubscriptionCreate(BaseModel):
    name:str=Field(min_length=2,max_length=120); azure_subscription_id:str=Field(min_length=8); environment:Literal["dev","staging","prod"]; credential_ref:str|None=None
class SubscriptionRead(SubscriptionCreate,ORM): id:int; is_active:bool
class PolicyCreate(BaseModel):
    name:str; rule_type:Literal["required_tags","open_nsg_port"]; severity:Literal["low","medium","high","critical"]; config:dict; auto_remediate:bool=False
    @model_validator(mode="after")
    def validate_config(self):
        if self.rule_type=="required_tags" and not self.config.get("required_tags"): raise ValueError("required_tags is required")
        if self.rule_type=="open_nsg_port" and not self.config.get("ports"): raise ValueError("ports is required")
        if self.auto_remediate and self.severity in {"high","critical"}: raise ValueError("high/critical rules cannot auto-remediate")
        return self
class PolicyRead(PolicyCreate,ORM): id:int; enabled:bool
class ScanCreate(BaseModel): subscription_id:int
class ScanRead(ORM): id:int; subscription_id:int; trigger_source:str; status:str; started_at:datetime|None; completed_at:datetime|None; error:str|None
class FindingRead(ORM): id:int; scan_id:int; policy_rule_id:int; resource_id:str; resource_type:str; title:str; details:dict; severity:str; status:str; created_at:datetime
class ExceptionCreate(BaseModel): reason:str=Field(min_length=5); expires_at:datetime
class AuditRead(ORM): id:int; action:str; entity_type:str; entity_id:str; actor_id:int|None; data:dict; previous_hash:str; event_hash:str; created_at:datetime
