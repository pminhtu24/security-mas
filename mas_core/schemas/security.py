from typing_extensions import Literal
from pydantic import BaseModel
from typing import List, Optional


# ======================= Pydantic Schemas =======================

class CodeLocation(BaseModel):
    file_path: str
    start_line: int
    end_line: Optional[int] = None

class FixSuggestion(BaseModel):
    description: str
    patch: str | None = None

class SecurityIssue(BaseModel):
    tool: str
    risk_level: Literal["Critical","High","Medium","Low"]
    message: str
    location: Optional[CodeLocation] = None
    fix: Optional[FixSuggestion] = None

class LLMAnalysisResult(BaseModel):
    issues: List[SecurityIssue]
    overall_risk: str
    remediation_priority: List[str]