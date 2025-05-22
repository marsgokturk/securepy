from flask import Flask, request, jsonify
import xml.etree.ElementTree as ET
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)


@app.route('/api/submit', methods=['POST'])
def submit_data():
    xml_data = request.data

    logging.info("Received XML data: %s", xml_data.decode())

    try:
        tree = ET.ElementTree(ET.fromstring(xml_data))
        root = tree.getroot()

        for element in root.findall('item'):
            name = element.find('name').text
            value = element.find('value').text
            logging.info("Processing item: name=%s, value=%s", name, value)

        return jsonify({"status": "success", "message": "Data processed"}), 200

    except ET.ParseError:
        logging.error("Failed to parse XML")
        return jsonify({"status": "error", "message": "Invalid XML data"}), 400


if __name__ == '__main__':
    app.run()