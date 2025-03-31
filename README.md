# 🔐 SecurePy: Agent-Based Python Code Vulnerability Scanner

**SecurePy** is an experimental tool that uses a multi-agent system to analyze Python code for security vulnerabilities and generate actionable reports. By integrating LLM-based reasoning with curated security knowledge, it performs thorough and systematic code reviews.

This project explores how LLMs can be safely and reliably used for automated code security auditing. It addresses real-world challenges in secure software development by simulating a reasoning pipeline designed to identify and correct insecure code.

---

## 🚀 Features

- Upload or paste Python code into a user-friendly Gradio interface.
- Automatically scans for known and emerging security issues.
- Calibrates results to minimize false positives.
- Suggests secure alternatives for identified vulnerabilities.
- Generates a structured Markdown report summarizing findings and recommendations.
---

## 🧠 Agent Pipeline Overview

This tool employs a four-stage agent pipeline to ensure precise and reliable vulnerability detection and response:

### 1. 🛡 Input Guardrail Agent
- Validates user input to filter out prompts with malicious intent, protecting the pipeline from prompt injection or adversarial inputs.

### 2. 🕵️ Code Analyzer Agent
- Scans code for the top 50 known vulnerability patterns.
- Proposes a new rule if it detects a vulnerability category that does not exist in the top 50 curated vulnerabilities.

### 3. 🎯 Response Calibration Agent
- Filters out likely false positives based on code context and known safe uses.

### 4. 🛠 Vulnerability Fix Agent
- Suggests secure, developer-friendly code fixes.
- Outputs a Markdown report with rationale and CWE references.

## 📄 Sample Output

You can view a sample generated Markdown report here:  
[model_outputs/insecure_example.md](model_outputs/insecure_example.md)

## 🧪 Use Cases
- Automating secure code reviews.
- Enhancing developer tooling for CI/CD pipelines. For instance, prior to merging into the main branch, this agent can review code and create a GitHub issue if a vulnerability is detected.

## 📚 Technologies
- Python 3.10+
- OpenAI GPT
- Gradio
- Markdown reporting

## 🔗 Gradio App Access

A public Gradio demo will be available soon. It includes several sample Python files and pre-generated security reports for demonstration purposes. The hosted version does not make live OpenAI API calls.

If you wish to experiment with your own Python files:
- Upload them to the `code_samples/` directory.
- Add your OpenAI API key to a `.env` file at the project root.
- Run the `run.py` script.
- The output will be written in Markdown format to the `model_outputs/` directory. Each file will be named after the corresponding input `.py` file.

This setup allows you to run the full agent pipeline locally with live model calls.

## 📂 Folder Structure

```
securepy/
├── run.py                # Main script to run the agent pipeline
├── agents/               # Agent modules (guardrail, analyzer, calibration, fixer)
├── code_samples/         # Python files to analyze
├── model_outputs/        # Markdown reports generated per input
├── schemas/              # Pydantic response models for agents
├── utils.py              # Shared utilities and helpers
├── data/                 # Security rule definitions (Top 50)
└── .env                  # OpenAI API key (user-provided)
```

## ⚠️ Disclaimer

This tool is intended for educational and developer productivity purposes. While it uses curated rule sets and LLM-based reasoning to detect vulnerabilities, it does not guarantee complete coverage or accuracy. Use at your own discretion.

## Author
Built by Mars Gokturk Buchholz, Applied AI Engineer. This project is part of a broader initiative to develop intelligent developer tools with a focus on security and usability.

## 📝 License

This project is licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).

If you use any part of the codebase or adapt ideas from this repository, please provide the following reference:

**Reference**:  
Buchholz, M. G. (2025). *SecurePy: Agent-Based Python Code Vulnerability Scanner*. GitHub Repository. https://github.com/yourusername/securepy
