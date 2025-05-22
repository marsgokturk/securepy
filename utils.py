import json

from schemas.fix import InsecureCodeFixResponse, CodeFix


def load_top_50_cwes(filepath="cwes.txt") -> str:
    with open(filepath, "r", encoding="utf-8") as f:
        cwe_ids = {line.strip().upper() for line in f if line.strip()}
    return cwe_ids

def load_top_50_rules(filepath="top_50_vulnerabilities.md") -> str:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    return content

def openai_chat(client,
                model:str,
                dev_message:str,
                user_messages:list,
                temperature:float,
                max_tokens:int,
                **kwargs):

    usr_msgs = [{"role": "developer", "content": [{"type": "text", "text": dev_message}]}]

    for message in user_messages:
        role = message[0]
        if role == "user":
            usr_msgs.append({"role": "user",  "content": [{"type": "text", "text": message[1]}]})
        elif role == "system":
            usr_msgs.append({"role": "system", "content": [{"type": "text", "text": message[1]}]})
        elif role == "tool":
            usr_msgs.append({"role": "tool",
                             "tool_call_id": message[1]["tool_call_id"],
                             "content": [{"type": "text", "text": message[1]["content"]}]})
        elif role == "message":
            usr_msgs.append(message[1])


    if kwargs.get("response_format", None):
        completion = client.beta.chat.completions.parse(
            model=model,
            messages=usr_msgs,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
    else:
        completion = client.chat.completions.create(
            model=model,
            messages=usr_msgs,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )

    if completion.choices[0].message.tool_calls:
        tool = completion.choices[0].message.tool_calls[0]
        function_name = tool.function.name
        function_args = json.loads(tool.function.arguments)
        msg = completion.choices[0].message

        return {
            "kind": "tool_call",
            "function_name": function_name,
            "tool_call_id": tool.id,
            "function_args": function_args,
            "message": msg
        }

    return {
        "kind": "text",
        "success": completion.choices[0].finish_reason == "stop",
        "response": completion.choices[0].message.parsed if kwargs.get("response_format", None) else completion.choices[0].message.content
    }

def format_result_to_markdown(result: dict) -> str:

    if result.get("success") is not True:
        markdown = f"""# ❌ Analysis Failed

**Reason**: {result.get("rationale", "Unknown error.")}"""

        return markdown

    if result.get("secure"):
        markdown = """# 🔍 Secure Code Agent Report

## 🧪 Verdict
✅ The submitted code is **secure**.
*No issues were detected.*"""

        return markdown

    # Insecure code case
    insecure_code_response: InsecureCodeFixResponse = result.get("fixes", None)
    if not insecure_code_response or not insecure_code_response.issues:
        markdown = "# ⚠️ The code was marked insecure, but no fix suggestions were returned.\n"

        return markdown

    markdown = [
        "# 🔍 Secure Code Agent Report",
        "\n## 🧪 Verdict",
        f"❌ The code contains **{len(insecure_code_response.issues)} security issue(s)** that need to be addressed.",
        "\n---",
        "\n## 🔒 Detected Issues and Fixes"
    ]

    for i, issue in enumerate(insecure_code_response.issues, start=1):
        issue:CodeFix = issue
        markdown.append(f"""
### {i}. {issue.issue}
**Problem**: {issue.description}

**Vulnerable Code**: 
```python
{issue.vulnerable_code}
```
**Root Cause**: {issue.root_cause}
**Consequence**: {issue.consequence}

**🔧 Suggested Fix:**
```python
{issue.suggested_code}
```
**Why This Works**: {issue.fix_explanation}
**Further Reading**:  {issue.cwe}""")

    full_markdown = "\n".join(markdown)

    return full_markdown
