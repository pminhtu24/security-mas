from typing_extensions import Literal
from pydantic import BaseModel, Field
from typing import List, Optional


# ======================= Pydantic Schemas =======================

class CodeLocation(BaseModel):
    file_path: str = Field(
        description="Relative or absolute path to the vulnerable file"
    )
    start_line: int = Field(
        description="Line number where the vulnerability starts (use 0 if unknown)"
    )
    end_line: Optional[int] = Field(
        default=None,
        description="Line number where the vulnerability ends (optional)"
    )

class FixSuggestion(BaseModel):
    description: str = Field(
        description="Detailed explanation of how to fix the issue, including specific code changes or commands",
        examples=[
            "Replace string formatting with parameterized queries using SQLAlchemy text() with bound parameters",
            "Run: pip install requests==2.31.0 to upgrade to patched version",
            "Use Jinja2 auto-escaping: {{ user_input | e }} instead of raw HTML concatenation"
        ]
    )
    patch: Optional[str] = Field(
        default=None,
        description="""Unified diff format patch (optional, for code fixes only). Format:
--- a/path/to/file.py
+++ b/path/to/file.py
@@ -line,count +line,count @@
-removed line
+added line

Leave as null for dependency issues or when concrete patch cannot be generated.""",
        examples=[
            "--- a/app.py\n+++ b/app.py\n@@ -10,2 +10,3 @@\n-query = f\"SELECT * FROM users WHERE id={uid}\"\n+query = \"SELECT * FROM users WHERE id=?\"\n+cursor.execute(query, [uid])"
        ]
    )

class SecurityIssue(BaseModel):
    tool: str = Field(
        description="Source scanning tool that detected this issue",
        examples=["Semgrep", "Snyk", "Manual Review"]
    )
    risk_level: Literal["Critical", "High", "Medium", "Low"] = Field(
        description="Severity level based on exploitability and impact"
    )
    message: str = Field(
        description="Clear, concise description of the vulnerability",
        examples=[
            "SQL injection via string formatting in user authentication",
            "XSS vulnerability in comment rendering without escaping",
            "Outdated dependency with known RCE vulnerability"
        ]
    )
    location: Optional[CodeLocation] = Field(
        default=None,
        description="Code location (required for SAST issues, null for SCA dependency issues)"
    )
    fix: Optional[FixSuggestion] = Field(
        default=None,
        description="Actionable fix with description and optional patch"
    )

class LLMAnalysisResult(BaseModel):
    issues: List[SecurityIssue] = Field(
        description="Unified, deduplicated list of security issues with actionable fixes"
    )
    overall_risk: Literal["Critical", "High", "Medium", "Low"] = Field(
        description="Overall project security risk (use highest severity found)"
    )
    remediation_priority: List[str] = Field(
        description="""Prioritized list of 3-5 specific remediation actions. 
Each action should be concrete and actionable, e.g.:
- 'Fix SQL injection in auth.py line 45 by using parameterized queries'
- 'Upgrade requests from 2.25.0 to 2.31.0 (pip install requests==2.31.0)'
- 'Replace pickle deserialization with JSON in data_handler.py'""",
        min_length=3,
        max_length=5,
        examples=[
            [
                "Immediately fix Critical SQL injection in app.py:45 using bound parameters",
                "Upgrade Django from 3.1.0 to 3.2.20 to patch CVE-2023-12345",
                "Replace insecure pickle usage with JSON serialization in cache.py",
                "Add input validation and escaping for all user-facing forms",
                "Enable SAST/SCA in CI/CD pipeline to prevent regression"
            ]
        ]
    )