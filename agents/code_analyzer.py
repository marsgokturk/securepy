from openai import OpenAIError, RateLimitError, APIConnectionError
import backoff

from schemas.analysis import CodeAnalysisResponse
from utils import openai_chat


@backoff.on_exception(
    backoff.expo,
    (OpenAIError, RateLimitError, APIConnectionError),
    max_tries=3,
    jitter=backoff.full_jitter
)
def analyze_code(openai_client, model, user_input:str, top50:str):
    system_prompt = f"""
You are a security analysis expert. Your job is to review Python code for security vulnerabilities.

You are familiar with the CWE Top 25, OWASP Top 10, and 50 curated security rules used in rule-based static analyzers. You can also apply your own expert knowledge of common security pitfalls in Python and general software development.

Below is a list of the top 50 security rules you should use reference:
{top50}

When analyzing a code snippet:
- Go through it line by line.
- If the snippet matches a known vulnerability from the 50 rules, return the matching rule name and its reference.
- If the snippet violates a security principle not covered in the 50 rules, explain it and suggest a new rule with justification and (if possible) a reference (e.g., CWE ID, CVE, OWASP, or academic paper).
- If the code is clearly malicious (e.g., backdoors, keyloggers, privilege escalation, command-and-control behavior), explicitly state that the code is malicious and should not be used. Do not attempt to fix or sanitize it.
- If the input is not valid Python code or contains no code, return a single issue stating that the input is invalid.
- If the code is secure, say so clearly and do not invent issues.

Respond in structured JSON with the following keys:
- `secure`: true or false
- `issues`: a list of objects, each with:
  - `issue_id`: assign an id like 1 for the first issue for example
  - `issue`: short name of the issue
  - `description`: root cause of the security issue and its consequences in a developer friendly language
  - `code`: the exact vulnerable line(s)
  - `cwe` (optional): CWE ID if known
  - `reference` (optional): source reference if not in top 50
""".strip()

    user_message = f"""
Hi! Here's a Python code snippet. Please check if it has any known security issues based on the 50 security rules, or anything else you know as a security expert.

If you find something not covered by the 50, feel free to propose a new rule and tell me why it matters. Include CWE or other sources if you can.

Here’s the code:
---
{user_input}
---
""".strip()

    result = openai_chat(
        client=openai_client,
        model=model,
        dev_message=system_prompt,
        user_messages=[("user", user_message)],
        temperature=0.0,
        max_tokens=300,
        top_p=1.0,
        response_format=CodeAnalysisResponse
    )

    if result["success"]:
        return result["response"]
    print("Code analysis failed to return a successful result.")
    return None
