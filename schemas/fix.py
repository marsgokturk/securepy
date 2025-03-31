from typing import List

from pydantic import BaseModel


class CodeFix(BaseModel):
    issue: str
    description: str
    vulnerable_code: str
    cwe: str
    root_cause: str
    consequence: str
    suggested_code: str
    fix_explanation: str

    def __str__(self):
        return (
            f"Issue #{self.issue} ({self.cwe})\n"
            f"Description: {self.description}\n"
            f"Vulnerable Code:\n{self.vulnerable_code}\n"            
            f"Root Cause: {self.root_cause}\n"
            f"Consequence: {self.consequence}\n"
            f"Suggested code: {self.suggested_code}\n"
            f"Fix Explanation: {self.fix_explanation}"
        )

class InsecureCodeFixResponse(BaseModel):
    issues: List[CodeFix]
