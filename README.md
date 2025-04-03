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

# 🔐 SecurePy: Agent-Based Python Code Vulnerability Scanner

**SecurePy** is an experimental tool that uses a multi-agent system to analyze Python code for security vulnerabilities and generate actionable reports. By integrating LLM-based reasoning with curated security knowledge, it performs thorough and systematic code reviews.

This project explores how LLMs can be safely and reliably used for automated code security auditing. It addresses real-world challenges in secure software development by simulating a reasoning pipeline designed to identify and correct insecure code.

## 🔍 Try it out

Try SecurePy instantly in your browser:  
[**🔗 Launch the Hugging Face Demo**](https://huggingface.co/spaces/marz1/securepy-demo)
- Select from preloaded Python code samples representative of common security flaws.
- Trigger the vulnerability detection pipeline using the "Scan for Vulnerabilities" button.
- Review structured Markdown reports that summarize detected vulnerabilities, CWE mappings, and remediation suggestions.
- Clone and run locally to experiment with your own files or extend the agent pipeline.

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

## 🔗Gradio App Access
A hosted Gradio demo is publicly available and includes curated sample Python files with pre-generated security reports. The hoster version does not make live OpenAI calls.
To experiment with your own Python code and enable live model inference:
- Upload them to the `code_samples/` directory.
- Add your OpenAI API key to a `.env` file at the project root.

- The output will be written in Markdown format to the `model_outputs/` directory. Each file will be named after the corresponding input `.py` file.
this configuration enables the full agent pipeline with real-time LLM reasoning.

## 🧪 Use Cases
- Automating secure code reviews.
- Enhancing developer tooling for CI/CD pipelines. For instance, prior to merging into the main branch, this agent can review code and create a GitHub issue if a vulnerability is detected.

## 📚 Technologies
- Python 3.10+
- OpenAI GPT
- Gradio
- Markdown reporting

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
