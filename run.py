from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

from agents.code_analyzer import analyze_code
from agents.input_guardrail import input_guardrail
from agents.response_calibration_agent import review_security_response, process_review
from agents.vuln_fixer import suggest_secure_fixes
from schemas.analysis import CodeAnalysisResponse, CalibrationResponse, CalibratedCodeAnalysisResponse
from schemas.fix import InsecureCodeFixResponse
from utils import load_top_50_rules, format_result_to_markdown


def run(openai_client, code_snippet, model, top50_rules):

    # 1. Validate user intent
    result, rationale = input_guardrail(openai_client, model, user_input=code_snippet)
    if result != "success":
        return {
            "success": False,
            "step": "guardrail",
            "user_input": code_snippet,
            "rationale": rationale
        }

    # 2. Analyze the code
    code_analysis:CodeAnalysisResponse = analyze_code(openai_client, model=model, user_input=code_snippet, top50=top50_rules)
    if code_analysis.secure:
        return {
            "success": True,
            "step": "analyzer",
            "secure": True,
            "message": "The code is secure according to analysis."
        }

    # 3. Calibrate the analysis
    calibration_response:CalibrationResponse = review_security_response(openai_client=openai_client, model=model, code_analysis=code_analysis)
    calibrated_analysis:CalibratedCodeAnalysisResponse = process_review(code_analysis=code_analysis, calibration_response=calibration_response)
    if calibrated_analysis.secure:
        return {
            "success": True,
            "step": "calibration",
            "secure": True,
            "message": "The code is secure according to calibration. Initial findings were rejected or found to be speculative."
        }

    # 4. Generate secure code fixes
    fix_suggestions:InsecureCodeFixResponse = suggest_secure_fixes(openai_client=openai_client, model=model, code=code_snippet, analysis=calibrated_analysis)
    return {
        "success": True,
        "step": "fix_suggestions",
        "secure": False,
        "fixes": fix_suggestions
    }

def test_with_code_file(filepath:str, label:str, openai_client:OpenAI,model:str, top50_rules:str ):
    print(f"\n===== Running test: {label} =====")
    with open(filepath, "r", encoding="utf-8") as f:
        code = f.read()
    try:
        result = run(openai_client=openai_client, code_snippet=code, model=model, top50_rules=top50_rules)
        return result
    except Exception as e:
        print(f"❌ Test '{label}' failed: {e}")

if __name__ == "__main__":

    load_dotenv(override=True)
    client = OpenAI()
    model = "gpt-4o-2024-08-06"
    top50_path = Path(__file__).parent / "data" / "top_50_vulnerabilities.md"
    top50 = load_top_50_rules(filepath=top50_path)

    test_files_dir = Path("code_samples")
    output_dir = Path("model_outputs")
    output_dir.mkdir(exist_ok=True)

    for filepath in test_files_dir.glob("*.py"):
        filename = filepath.name.replace(".py", "")
        result: dict = test_with_code_file(str(filepath), label=filename, openai_client=client, model=model, top50_rules=top50)
        print(result)

        markdown = format_result_to_markdown(result=result)
        output_path = output_dir / f"{filename}.md"
        output_path.write_text(markdown, encoding="utf-8")
