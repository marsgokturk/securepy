import json
from pathlib import Path
from tqdm import tqdm

from openai import OpenAI
from dotenv import load_dotenv
from utils import load_top_50_cwes, load_top_50_rules

from pipeline.code_analyzer import analyze_code
from pipeline.input_guardrail import input_guardrail
from pipeline.response_calibration_agent import review_security_response, process_review
from schemas.analysis import CodeAnalysisResponse, CalibrationResponse, CalibratedCodeAnalysisResponse, VerdictEnum
import time


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
    if len(code_analysis.issues) == 0:
        return {
            "success": True,
            "step": "analyzer",
            "secure": True,
            "message": "The code is secure according to analysis."
        }

    # 3. Calibrate the analysis
    calibration_response:CalibrationResponse = review_security_response(openai_client=openai_client, model=model, code=code_snippet, code_analysis=code_analysis, top_50_descriptions=top50_rules)
    calibrated_analysis:CalibratedCodeAnalysisResponse = process_review(code_analysis=code_analysis, calibration_response=calibration_response)
    return calibrated_analysis

def test_insecure(client, model, top50_rules, ground_truth):

    test_files = list(Path("vuln_code_samples").glob("*.py"))

    # --- Evaluation logic ---
    total = len(test_files)

    secure_detection_correct = 0
    cwe_detection_correct = 0
    total_with_cwe = 0

    per_file_results = []

    for path in tqdm(test_files):
        time.sleep(5)
        print(path)
        code = path.read_text()
        expected = ground_truth.get(path.name, {})
        expected_cwe = expected.get("cwe")

        result = run(openai_client=client, code_snippet=code, model=model, top50_rules=top50_rules)

        detected_issues = []
        if isinstance(result, CalibratedCodeAnalysisResponse) and not result.secure:
            secure_detection_correct += 1
            for issue in result.issues:
                pred_cwe = issue.cwe.replace("_", "-").upper()
                if issue.verdict == VerdictEnum.CONFIRMED:
                    detected_issues.append(pred_cwe)

        if expected_cwe:
            total_with_cwe += 1
            if expected_cwe.upper() in detected_issues:
                cwe_detection_correct += 1

        per_file_results.append({
            "file": path.name,
            "expected_cwe": expected_cwe,
            "detected_cwes": detected_issues,
            "secure": getattr(result, "secure", None)
        })

        print(f"File: {path.name}")
        print(f"  Expected CWE: {expected_cwe}")
        print(f"  Detected CWEs: {detected_issues}")
        print(f"  Secure? {getattr(result, 'secure', None)}")
        print()

    # Write markdown summary
    summary_md = Path("test_results/eval_insecure.md")
    with open(summary_md, "w", encoding="utf-8") as f:
        f.write("# Evaluation Summary\n\n")
        f.write(f"- **Files Tested**: {total}\n")
        f.write(f"- **Correctly Flagged Insecure**: {secure_detection_correct}/{total}\n")
        f.write(f"- **Correct CWE Found in Prediction**: {cwe_detection_correct}/{total_with_cwe}\n\n")
        f.write("## Per-File Results\n\n")
        f.write("| File | Expected CWE | Detected CWEs | Secure? |\n")
        f.write("|------|---------------|----------------|----------|\n")
        for result in per_file_results:
            f.write(
                f"| {result['file']} | {result['expected_cwe']} | {', '.join(result['detected_cwes'])} | {result['secure']} |\n")

    print(f"\n✅ Summary written to {summary_md}")

def test_secure(client, model, top50_rules):

    test_files = list(Path("vuln_code_fixed").glob("*.py"))

    # --- Evaluation logic ---
    total = len(test_files)

    true_positives = 0  # Correctly detected secure
    false_positives = 0  # Incorrectly marked as insecure

    per_file_results = []

    for path in tqdm(test_files):
        time.sleep(5)
        print(path)
        code = path.read_text()

        result = run(openai_client=client, code_snippet=code, model=model, top50_rules=top50_rules)

        is_secure_detected = (
            (isinstance(result, dict) and result.get("secure")) or
            (isinstance(result, CalibratedCodeAnalysisResponse) and result.secure)
        )

        if is_secure_detected:
            true_positives += 1
        else:
            false_positives += 1

        per_file_results.append({
            "file": path.name,
            "secure_detected": is_secure_detected
        })

        print(f"File: {path.name}")
        print(f"  Secure Detected? {is_secure_detected}")
        print()

    # Write markdown summary
    summary_md = Path("test_results/eval_secure.md")
    with open(summary_md, "w", encoding="utf-8") as f:
        f.write("# Evaluation Summary\n\n")
        f.write(f"- **Files Tested**: {total}\n")
        f.write(f"- **Correctly Flagged Secure (True Positives)**: {true_positives}/{total}\n")
        f.write(f"- **Incorrectly Flagged Insecure (False Positives)**: {false_positives}/{total}\n")

        f.write("## Per-File Results\n\n")
        f.write("| File | Secure Detected? |\n")
        f.write("|------|-------------------|\n")
        for result in per_file_results:
            f.write(f"| {result['file']} | {result['secure_detected']} |\n")

    print(f"\n✅ Summary written to {summary_md}")


if __name__ == "__main__":

    load_dotenv(override=True)
    client = OpenAI()
    model = "gpt-4o-2024-08-06"
    top50_rules = load_top_50_rules(filepath=Path(__file__).parent.parent / "data" / "top_50_vulnerabilities.md")
    top50_cwes = load_top_50_cwes(filepath=Path(__file__).parent.parent / "data" / "cwes.txt")
    ground_truth = json.load(open(Path("ground_truth.json")))

    test_insecure(client=client,
                  model=model,
                  top50_rules=top50_rules,
                  ground_truth=ground_truth)

    test_secure(client=client,
                model=model,
                top50_rules=top50_rules)

