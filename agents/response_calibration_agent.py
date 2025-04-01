from typing import Any

from openai import OpenAIError, RateLimitError, APIConnectionError
import backoff

from agents.code_analyzer import CodeAnalysisResponse
from schemas.analysis import CalibrationResponse, CalibratedCodeAnalysisResponse, ReviewedCodeAnalysis, CodeIssue
from utils import openai_chat

@backoff.on_exception(
    backoff.expo,
    (OpenAIError, RateLimitError, APIConnectionError),
    max_tries=3,
    jitter=backoff.full_jitter
)
def review_security_response(openai_client, model: str, code_analysis: CodeAnalysisResponse) -> Any | None:
    system_prompt = """
You are a response calibration agent. Your job is to review the outputs of a primary security analysis agent that detects vulnerabilities in Python code.

You act as a critical verifier, ensuring that the primary agent's assessment is well-calibrated. You must be conservative with claims — flagging real vulnerabilities is important, but **false positives must be avoided**.

When reviewing each issue raised by the primary agent, follow these principles:

- If the identified vulnerability is clearly supported by the code and matches known patterns (e.g., CWE rules), confirm it.
- If the issue is **possible but not evident from the code alone**, flag it as **speculative** and explain what additional context is needed.
- You should not assume authentication exists unless it is clearly shown or enforced in the code. 
- Privileged operations (e.g., updating EC2 public IPs, role changes, user deletion) must have explicit authorization logic (e.g., token validation, role check).

Be especially cautious with:
- Flagging code that does not directly contain insecure logic (e.g., `import secret_info`)
- Overgeneralizing security advice without clear indicators from the code

Your output should include:
1. A **final verdict** for each issue: `"confirmed"`, `"warning (speculative)"`, or `"rejected (false positive)"`
2. A **justification** for the verdict
3. A **suggested correction**, if applicable (e.g., rephrased diagnosis or demoted severity)

Respond in structured JSON like this:

```json
{
  "review": [
    {
      "issue_id": <issue id from the primary agent's assessment>,
      "verdict": <confirmed, warning (speculative), or rejected (false positive)>,
      "justification": <justification for your verdict in 1-2 sentences>
      "suggested_action": <best action to take based on the verdict>
    }
}
"""
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
        top_p=1.0,
        response_format=CalibrationResponse
    )

    if result["success"]:
        return result["response"]
    else:
        print("Calibration failed to return a successful result.")
        return None


def process_review(code_analysis: CodeAnalysisResponse, calibration_response: CalibrationResponse)-> CalibratedCodeAnalysisResponse:

    calibrated_code_analysis = CalibratedCodeAnalysisResponse(
        secure=False,
        issues=[]
    )

    for i, analysis in enumerate(code_analysis.issues):

        issue_is_found_in_verdicts = False

        for verdict in calibration_response.verdicts:

            if verdict.issue_id == analysis.issue_id:
                issue_is_found_in_verdicts = True

                issue = ReviewedCodeAnalysis(
                    issue_id=analysis.issue_id,
                    issue=analysis.issue,
                    description=analysis.description,
                    code=analysis.code,
                    cwe=analysis.cwe,
                    reference=analysis.reference,
                    verdict=verdict.verdict,
                    verdict_justification=verdict.justification,
                    suggested_action=verdict.suggested_action
                )
                calibrated_code_analysis.issues.append(issue)

        if not issue_is_found_in_verdicts:
            print(f"Verdict for the issue: {analysis.issue_id} is not found.")

    all_secure = True
    for issue in calibrated_code_analysis.issues:
        if issue.verdict == "confirmed":
            all_secure = False

    calibrated_code_analysis.secure = True if all_secure else False
    return calibrated_code_analysis
