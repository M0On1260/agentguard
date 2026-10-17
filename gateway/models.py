from typing import Literal
from pydantic import BaseModel


class ToolCall(BaseModel):
    session_id: str
    tool: str
    arg: str = ""


class ScanRequest(BaseModel):
    session_id: str
    tool: str
    output: str


class Decision(BaseModel):
    verdict: Literal["allow", "block", "approve"]
    rule_id: str
    reason: str
