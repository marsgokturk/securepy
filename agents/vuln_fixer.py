from typing import Any

from schemas.analysis import CalibratedCodeAnalysisResponse
from schemas.fix import InsecureCodeFixResponse
from utils import openai_chat
from openai import OpenAIError, RateLimitError, APIConnectionError
import backoff

@backoff.on_exception(
    backoff.expo,
    (OpenAIError, RateLimitError, APIConnectionError),
    max_tries=3,
    jitter=backoff.full_jitter
)
def suggest_secure_fixes(openai_client, model: str, code: str, analysis: CalibratedCodeAnalysisResponse) -> Any | None:
    """
    Given insecure code and calibrated findings, suggest secure alternatives and explanations.
    """
    system_prompt = """
You are a secure code suggestion assistant. Your job is to take in a piece of Python code and a set of validated security findings, 
and return secure code alternatives along with clear explanations.
    
You will receive:
1. The original Python code (containing one or more security vulnerabilities)
2. A list of security issues confirmed or flagged as speculative by a calibration agent. Each issue includes:
   - The issue name
   - Description
   - The vulnerable line(s)
   - CWE identifier and reference
   - Justification of the problem

For each issue:
- Suggest a secure version of the vulnerable line(s) or section. Make sure the code is formatted correctly.
- Clearly explain:
  - Why the original code is insecure
  - What CWE it maps to
  - What consequences it might lead to if not fixed
  - How your suggested code mitigates the vulnerability
- When suggesting fixes, make sure your fix does not introduce new vulnerabilities. Carefully review the context of the surrounding code and ensure the new code is secure and consistent with secure coding best practices.

Return your response as a structured JSON object in this format:

{
  "fixes": [
    {
      "issue": "SQL Injection (CWE-89)",
      "description": "...",
      "vulnerable_code": "...",      
      "root_cause": "...",
      "consequence": "...",
      "suggested_code": "...",
      "fix_explanation": "..."
    }
  ]
}
""".strip()

    user_message = f"""
    Original Code:
    ```python
    {code}
    ```

    Validated Issues:
    {analysis.model_dump_json(indent=2)}
    """.strip()

    response = openai_chat(
        client=openai_client,
        model=model,
        dev_message=system_prompt,
        user_messages=[("user", user_message)],
        temperature=0.0,
        max_tokens=1000,
        top_p=1.0,
        response_format=InsecureCodeFixResponse
    )

    if response["success"]:
        return response["response"]
    print("Vulnerability fixer failed to return a successful result.")
    return None
