from pathlib import Path

import gradio as gr


test_files_dir = Path("code_samples")
output_dir = Path("model_outputs")
default_file = next(test_files_dir.glob("*.py"), None)

with gr.Blocks() as demo:
    gr.Markdown("## SecurePy Demo\nScan Python code for vulnerabilities using precomputed SecurePy outputs. This demo does not run live inference.")

    code_file_dropdown = gr.Dropdown(
        choices=[f.name for f in test_files_dir.glob("*.py")],
        value=default_file.name if default_file else None,
        label="Select a sample Python code to be scanned",
        interactive=True
    )

    code_display = gr.Code(label="Source Code", lines=20, interactive=False, language="python")
    output_header = gr.Markdown("## 🧠 Model Output")
    code_output = gr.Markdown()

    def load_code_and_output(file_name):
        code_content = (test_files_dir / file_name).read_text(encoding="utf-8")
        output_content = (output_dir / file_name.replace(".py", ".md")).read_text(encoding="utf-8")
        return code_content, "## 🧠 Model Output", output_content

    code_file_dropdown.change(fn=load_code_and_output, inputs=code_file_dropdown, outputs=[code_display, output_header, code_output])

demo.launch()