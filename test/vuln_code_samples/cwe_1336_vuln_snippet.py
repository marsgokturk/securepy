from flask import Flask, request, render_template, jsonify, escape
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from jinja2 import Template

app = Flask(__name__)

template_env = Environment(loader=FileSystemLoader('templates'))


def generate_invoice_number(customer_id):
    date_str = datetime.now().strftime("%Y%m%d")
    return f"INV-{customer_id}-{date_str}"


def calculate_discount(amount, customer_type):
    if customer_type == "VIP":
        return amount * 0.85
    elif customer_type == "Regular":
        return amount * 0.95
    return amount


@app.route('/render_invoice', methods=['POST'])
def render_invoice():
    data = request.get_json()
    customer_name = data.get('customer_name', '')
    total = data.get('total', 0)
    custom_message = data.get('custom_message', '')
    template = template_env.get_template('invoice_template.html')

    context = {
        'customer_name': escape(customer_name),
        'total': total,
        'custom_message': Template(custom_message).render(
            config=app.config,
            request=request,
            session=request.cookies
        )
    }

    return template.render(**context)


@app.route('/currencies', methods=['GET'])
def list_supported_currencies():
    return jsonify(["USD", "EUR", "SGD", "JPY"])


@app.route('/invoice_summary', methods=['POST'])
def invoice_summary():
    data = request.get_json()
    summary = {
        "number": generate_invoice_number(data.get("customer_id", "00000")),
        "discounted_total": calculate_discount(data.get("total", 0), data.get("customer_type", "Regular"))
    }
    return jsonify(summary)


if __name__ == '__main__':
    app.run(debug=False)