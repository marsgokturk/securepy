from typing import Any

from openai import OpenAIError, RateLimitError, APIConnectionError
import backoff

from pipeline.code_analyzer import CodeAnalysisResponse
from schemas.analysis import CalibrationResponse, CalibratedCodeAnalysisResponse, ReviewedCodeAnalysis
from utils import openai_chat

@backoff.on_exception(
    backoff.expo,
    (OpenAIError, RateLimitError, APIConnectionError),
    max_tries=3,
    jitter=backoff.full_jitter
)
def review_security_response(openai_client, model: str, code:str, code_analysis: CodeAnalysisResponse, top_50_descriptions:str) -> Any | None:
    system_prompt = f"""
You are an expert cyber security analyst specializing in Python code.  
Your job is to critically verify issues flagged by a primary security analysis agent, using the actual Python code as evidence.

---

### INPUTS:

- **Python Source Code** (`python_code`): Full or partial codebase to be reviewed.
- **Flagged Issues List** (`flagged_issues`): Each issue includes its finding, related code range/snippet, vulnerability type, and unique issue ID.
- **Top 50 Vulnerabilities List** (`top_50_descriptions`): The accepted set of vulnerability types and their criteria.  
  _See below for a sample excerpt:_

---
#### Python Code ('python_code')
{{code}}
---

---
#### Top 50 Critical Security Rules for Python Code Analysis ('top_50_descriptions')
{{top_50_descriptions}}
---

### YOUR TASK:

For each issue in `flagged_issues`:

1. **Locate Evidence in Code:**  
   - Examine the flagged code snippet or line(s) within 'python_code'.
   - Look for clear, direct evidence of the behavior described in the flagged finding.
   - If the issue is related to authentication or authorization; the evidence of these being implemented correctly must exist in the given python_code.

2. **Vulnerability Matching:**  
   - Confirm alignment to the corresponding entry in 'top_50_descriptions'.

3. **Assessment Principles:**  
- **Confirmed**:    
    - Classify as "confirmed" if:
        - The insecure behavior (e.g., missing input validation, direct command/SQL execution, weak crypto, etc.) is explicitly present in the given python_code.
        - Or a critical/privileged action (such as access/modification of sensitive data, role assignments, admin actions, etc.) is performed without any direct evidence of robust authentication and/or authorization logic in the same code.
    - Do not assume protection exists unless it is clearly implemented in the provided code. "Security elsewhere" is not valid unless it is visible in the review scope.
    - Example: If the code retrieves, updates, deletes, or otherwise manages user data or privileged resources and there is no authentication/authorization logic shown, this is a "confirmed" case of "Missing Authentication" or "Missing Authorization" per the Top 50 definitions.
- **Warning (Speculative)**:
    - Use "warning (speculative)" only if there is code that could possibly be protected elsewhere, and there are hints of such protection (e.g., a decorator, a call to a possibly-authenticating function, or a framework mention)—but the effectiveness or presence of this logic is not fully shown or verifiable in the supplied code.
    - Also use this if the top 50 rule’s applicability depends on configuration or runtime context not included in the code.
- **Rejected (False Positive)**:
    - If the code does not perform the flagged behavior, or implements all necessary secure practices as per the top 50 criteria, assign "rejected (false positive)".

4. **Special caution:**  
    - Do not assume authentication or authorization is enforced unless you see direct evidence in the inspected code. If a sensitive/privileged operation is performed with no such check visible, always classify as "confirmed" (Missing Authentication or Authorization) as per secure-by-design and the Top 50 rules. Speculative warnings are only for cases where security protection is present or hinted at but its effectiveness or actual implementation cannot be determined from the code snippet provided.     - Only confirm privilege-sensitive operations (user admin, role modification, credential changes, environment/infra changes) if direct, robust authorization logic is present.
    - No confirmation for general, indirect, or hypothetical issues unless the actual code logic is insecure as per the top 50 criteria.

5. **Recommendation:**  
   - For every issue, suggest the best action: remediation step, need for more data, or dismiss the finding.
---

### OUTPUT STRUCTURE

Return a single JSON object:

```json
{{
  "review": [
    {{
      "issue_id": "<from primary agent’s finding>",
      "verdict": "<confirmed | warning (speculative) | rejected (false positive)>",
      "justification": "<1-2 sentence explanation referencing the actual code and top-50 criteria>",
      "suggested_action": "<fix, collect more info, reclassify, or dismiss>"
    }}
  ]
}}
""".strip()

    user_message = f"""
    Primary security agent review:
    ---
    {str(code_analysis)}
    ---
    """.strip()

    result = openai_chat(
        client=openai_client,
        model=model,
        dev_message=system_prompt,
        user_messages=[("user", user_message)],
        temperature=0.0,
        max_tokens=500,
        response_format=CalibrationResponse
    )

    if result["success"]:
        return result["response"]
    else:
        print("Calibration failed to return a successful result.")
        return None


def process_review(code_analysis: CodeAnalysisResponse, calibration_response: CalibrationResponse)-> CalibratedCodeAnalysisResponse:
    """
    Filters issues based on the 'confirmed' verdict from the calibration, and updates the overall security status.

    Args:
        code_analysis: The initial code analysis response from the primary agent.
        calibration_response: The calibration response after LLM review.

    Returns:
        A CalibratedCodeAnalysisResponse with issues filtered by 'confirmed'
        verdicts and an updated 'secure' status.
    """

    calibrated_code_analysis = CalibratedCodeAnalysisResponse(
        secure=code_analysis.secure,
        issues=[]
    )

    for verdict in calibration_response.verdicts:
        issue_id = verdict.issue_id
        verdict_decision = verdict.verdict
        if verdict_decision == "confirmed":
            for issue in code_analysis.issues:
                if issue.issue_id == issue_id:
                    iss = ReviewedCodeAnalysis(
                        issue_id=issue_id,
                        issue=issue.issue,
                        description=issue.description,
                        code=issue.code,
                        cwe=issue.cwe if issue.cwe else "",
                        reference=issue.reference,
                        verdict=verdict_decision,
                        verdict_justification=verdict.justification,
                        suggested_action=verdict.suggested_action
                    )
                    calibrated_code_analysis.issues.append(iss)
                    break

    calibrated_code_analysis.secure = len(calibrated_code_analysis.issues) == 0

    return calibrated_code_analysis
