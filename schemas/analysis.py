from enum import Enum
from typing import Optional, List

from pydantic import BaseModel

class CodeIssue(BaseModel):
    issue_id:int
    issue: str
    description: str
    code: str
    cwe: Optional[str] = None
    reference: str

    def __str__(self):
        return (
            f"Issue #{self.issue_id}: {self.issue} ({self.cwe})\n"
            f"Description: {self.description}\n"
            f"Vulnerable Code:\n{self.code}\n"
            f"Reference: {self.reference}\n"
        )

class CodeAnalysisResponse(BaseModel):
    secure: bool
    issues: List[CodeIssue]

    def __str__(self):
        status = "✅ Code is Secure" if self.secure else "❌ Code has Security Issues"
        issues_str = "\n\n".join(str(issue) for issue in self.issues)
        return f"{status}\n\n{issues_str}"


class VerdictEnum(str, Enum):
    CONFIRMED = "confirmed"
    SPECULATIVE = "warning (speculative)"
    FALSE_POSITIVE = "rejected (false positive)"


class ReviewedCodeAnalysis(BaseModel):
    issue_id:int
    issue: str
    description: str
    code: str
    cwe: str
    reference: str
    verdict:str
    verdict_justification: str
    suggested_action: str

    def __str__(self):
        return (
            f"Issue #{self.issue_id}: {self.issue} ({self.cwe})\n"
            f"Description: {self.description}\n"
            f"Vulnerable Code:\n{self.code}\n"
            f"Verdict: {self.verdict}\n"
            f"Justification: {self.verdict_justification}\n"
            f"Suggested Action: {self.suggested_action or 'N/A'}\n"
            f"Reference: {self.reference}\n"
        )

class CalibratedCodeAnalysisResponse(BaseModel):
    secure: bool
    issues: List[ReviewedCodeAnalysis]

    def __str__(self):
        status = "✅ Code is Secure" if self.secure else "❌ Code has Security Issues"
        issues_str = "\n\n".join(str(issue) for issue in self.issues)
        return f"{status}\n\n{issues_str}"

class ReviewVerdict(BaseModel):
    issue_id: int
    verdict: VerdictEnum
    justification: str
    suggested_action: str = None

class CalibrationResponse(BaseModel):
    verdicts: List[ReviewVerdict]
