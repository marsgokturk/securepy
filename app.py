from pathlib import Path

import gradio as gr

test_files_dir = Path("demo/inputs")
output_dir = Path("demo/outputs")
default_file = next(test_files_dir.glob("*.py"), None)

with gr.Blocks() as demo:
    gr.Markdown("## SecurePy Demo\nScan Python code for vulnerabilities using precomputed SecurePy outputs. This demo does not run live inference.")

    code_file_dropdown = gr.Dropdown(
        choices=[f.name for f in test_files_dir.glob("*.py")],
        value=default_file.name if default_file else None,
        label="Select a sample Python code to be scanned for vulnerabilities",
        interactive=True
    )

    with gr.Row():
        with gr.Column():
            code_display = gr.Code(label="Source Code", lines=20, interactive=False, language="python")
            code_display.value = (test_files_dir / default_file.name).read_text(encoding="utf-8") if default_file else ""
            scan_button = gr.Button("🔍 Scan for Vulnerabilities")
        with gr.Column():
            output_header = gr.Markdown("## 🧠 Model Output")
            code_output = gr.Markdown()

    def load_code_only(file_name):
        code_content = (test_files_dir / file_name).read_text(encoding="utf-8")
        return code_content, "## 🧠 Model Output", "Click **Scan for Vulnerabilities** to see the results."

    def load_output_only(file_name):
        output_content = (output_dir / file_name.replace(".py", ".md")).read_text(encoding="utf-8")
        return "## 🧠 Model Output", output_content

    code_file_dropdown.change(fn=load_code_only, inputs=code_file_dropdown, outputs=[code_display, output_header, code_output])
    scan_button.click(fn=load_output_only, inputs=code_file_dropdown, outputs=[output_header, code_output])

demo.launch(share=True)
