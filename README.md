---
title: SecurePy
emoji: 🛡️
colorFrom: gray
colorTo: blue
sdk: gradio
sdk_version: "5.23.2"
app_file: app.py
pinned: true
---

# 🔐 SecurePy: LLM-Based Python Code Vulnerability Scanner

SecurePy is an experimental tool and research prototype where we use a 4-step LLM pipeline to analyze Python code for security vulnerabilities and generate actionable reports. By integrating Large Language Model (LLM)-based reasoning with our curated security knowledge, we perform structured code reviews and explore how LLMs can be safely and reliably used for automated code security auditing.

## Background: LLM-based Static Vulnerability Scanners for Python

In developing SecurePy, we're building on a significant and rapidly growing body of research that leverages Large Language Models (LLMs) for static vulnerability detection in source code [1]. Current research highlights that LLMs, through code structure analysis and pattern identification, offer a novel approach to vulnerability mitigation. They aim to overcome limitations of traditional static and dynamic analysis tools, such as high false-positive rates and scalability issues. Common methodologies in this field emphasize LLM implementation, prompt engineering, and semantic processing. While much of the LLM-based vulnerability detection research has focused on languages like C/C++ and Java, Python is an actively explored target, making up about 10.5% of studies in this area (as shown in Figure 5 of [1]). These studies often involve fine-tuning LLMs (like GPT, CodeLlama, and CodeBERT) on datasets of vulnerable code to classify functions or snippets. The main goal is to create systems that can accurately identify vulnerabilities, and sometimes even classify their type (e.g., by CWE) or predict severity. With SecurePy, we build upon this foundation by applying LLMs to Python code, focusing on file-level analysis.

## Dataset Considerations for SecurePy (File-Based Python Vulnerability Datasets):

For SecurePy, we curated a custom, file-based synthetic dataset, carefully cleaned of explicit hints, to serve as a targeted evaluation for our prototype. 
When searching for existing open-access Python datasets that align with our file-based analysis approach and provide CWE-specific labels, the landscape presents some challenges. 
Many existing vulnerability datasets commonly used in LLM research are function-level, such as BigVul and Devign, or commit-level, like CVEfixes. While CVEfixes does include Python and provides commit diffs which can offer broader context, it's primarily structured around code changes. The survey notes a general significant shortage of repository-level datasets that reflect real-world development scenarios where vulnerabilities often span multiple files and dependencies. While some datasets like the Juliet C/C++ and Java test suites are file-level and provide CWE labels, comprehensive Python equivalents in that specific format are less prominent in the surveyed literature. Existing datasets often have limitations such as being "narrowly scoped"  or primarily focusing on function-level analysis. Similarly, while new Python-specific datasets are emerging (e.g., Yıldırım2024 or Ullah2023 identified in Table 4 of the survey), these are also often function-level or synthesized snippets. Therefore, while SecurePy will be benchmarked against its custom dataset, future work will involve continued exploration for, or contribution towards, larger-scale, open-access, file-based Python vulnerability datasets with diverse CWE coverage suitable for evaluating tools that operate on entire files without relying on superficial code cues, addressing the need for datasets that better "simulate the real-world scenarios".

## Evaluation Results

We evaluated SecurePy's performance on the custom synthetic dataset (50 vulnerable and 49 secure Python files) described above. Our evaluation focused on the tool's ability to correctly identify files as vulnerable or secure and, for vulnerable files, predict the associated CWE or vulnerability type.

**Evaluation Summary (Custom Synthetic Dataset):**
* **Files Tested**: 99 (50 Vulnerable, 49 Secure)
* **Vulnerable Files Tested**: 50
* Correctly Flagged Insecure (True Positives): 44/50 (88% Recall)
* Correct CWE Found in Prediction: 38/50 (76%)
* **Secure Files Tested**: 49
* Correctly Flagged Secure (True Negatives): 42/49 (85.7% TN Rate)
* Incorrectly Flagged Insecure (False Positives): 7/49 (14.3% FP Rate on Secure Files)
**Derived Vulnerability Detection Metrics:**
* True Positives (TP): 44
* True Negatives (TN): 42
* False Positives (FP): 7
* False Negatives (FN): 6
* **Vulnerability Detection Precision**: **86.3%**
* **Vulnerability Detection Recall**: **88.0%**
* **Overall Accuracy**: **86.9%**

These results demonstrate the prototype's potential to identify a significant percentage of vulnerabilities in a controlled setting and distinguish between secure and insecure code with reasonable accuracy on this specific dataset. The ability to correctly identify the CWE for a high proportion of detected vulnerabilities (76%) is also promising for providing actionable remediation guidance.

## 🔍 Try it out

Try SecurePy instantly in your browser:  
[**🔗 Launch the Hugging Face Demo**](https://huggingface.co/spaces/marz1/securepy-demo)
- Select from preloaded Python code samples representative of common security flaws.
- Trigger the vulnerability detection pipeline using the "Scan for Vulnerabilities" button.
- Review structured Markdown reports that summarize detected vulnerabilities, CWE mappings, and remediation suggestions.
- Clone and run locally to experiment with your own files or extend the agent pipeline.

We designed this tool with a four-stage LLM pipeline to ensure precise and reliable vulnerability detection and response. It:
* Suggests secure, developer-friendly code fixes.
* Outputs a Markdown report with rationale and CWE references.

## 🧪 Use Cases

* Automating secure code reviews.
* Enhancing developer tooling for CI/CD pipelines (e.g., reviewing code before merge and creating a GitHub issue if a vulnerability is detected).

## 📚 Technologies

- Python 3.10+
- OpenAI GPT 4-o
- Gradio
- Markdown reporting

## 📂 Folder Structure

```
securepy/
├── run.py                # Main script to run the agent pipeline
├── pipeline/             # Modules (guardrail, analyzer, calibration, fixer)
├── schemas/              # Pydantic response models for agents
├── utils.py              # Shared utilities and helpers
├── data/                 # Security rule definitions (Top 50)
├── test/                 # Test files and test script
└── .env                  # OpenAI API key (user-provided)
```

## ⚠️ Disclaimer
We intend this tool for educational and developer productivity purposes. While it uses our curated rule sets and LLM-based reasoning to detect vulnerabilities, we cannot guarantee complete coverage or accuracy. Please use it at your own discretion.

## Author
Built by Mars Gokturk Buchholz, Applied AI Researcher. This project is part of a broader initiative to develop intelligent developer tools with a focus on security and usability.

## 📝 License

If you use any part of our codebase or adapt ideas from this repository, we ask that you please provide the following reference:
Buchholz, M. G. (2025). SecurePy: Agent-Based Python Code Vulnerability Scanner. GitHub Repository. https://github.com/marsgokturk/securepy

## References

[1] Hou, Y., Cleland-Huang, J., Wang, S., Li, Z., & Kroh, S. (2025). LLM-Based Vulnerability Detection: A Systematic Literature Review. arXiv preprint arXiv:2502.07049. Retrieved from https://arxiv.org/pdf/2502.07049
