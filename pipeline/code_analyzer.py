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
You are an expert cyber security analyst. Your task is to review the given Python file for security vulnerabilities defined in the below top 50 descriptions and return whether any of these issues are detected in the given code. 

---
# Top 50 vulnerabilities and Their Descriptions
Use the descriptions and CWE ids in this file to detect these issues in the given Python code:
{top50}
---

# Instructions
- Go through the Python code line by line. Understand the functionality. 
- If the code contains a known vulnerability from the top 50 vulnerabilities in the above, return the matching rule name and its reference.
- Pay attention to code segments that perform a critical function (e.g., configuration changes, file deletion, role or privilege updates, public IP assignments, security group modifications), check whether it includes appropriate validation, authentication or authorization. 
- If the code doesn't contain any of the vulnerabilities defined in the given 50 vulnerabilities, mark the code as secure and do not invent issues.

Respond in structured JSON with the following keys:
- `secure`: true if code contains any issues, false otherwise
- `issues`: a list of objects, each with:
  - `issue_id`: assign an id like 1 for the first issue for example
  - `issue`: short name of the issue
  - `description`: root cause of the security issue and its consequences in a developer friendly language
  - `code`: the exact vulnerable line(s)
  - `cwe`: CWE ID or Bandit issue reference extracted from the issue titles in the top 50 vulnerabilities, e.g CWE-78, Bandit-B321 etc.
  - `reference`: reference information extracted from the issues.
""".strip()

    user_message = f"""
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
        max_tokens=1000,
        response_format=CodeAnalysisResponse
    )

    if result["success"]:
        return result["response"]
    print("Code analysis failed to return a successful result.")
    return None
