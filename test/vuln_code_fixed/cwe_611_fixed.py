import defusedxml.ElementTree as ET
import json
import logging

logging.basicConfig(level=logging.INFO)


class XMLDataHandler:
    def __init__(self, xml_content):
        self.xml_content = xml_content

    def parse(self):
        try:
            tree = ET.fromstring(self.xml_content)
            return tree
        except Exception as e:
            logging.error(f"XML parsing failed: {e}")
            raise

    def get_root_tag(self):
        tree = self.parse()
        return tree.tag

    def extract_all(self):
        tree = self.parse()
        return {child.tag: child.text for child in tree}

    def to_json(self):
        data = self.extract_all()
        return json.dumps(data)


def save_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f)
    logging.info(f"Data saved to {filename}")


def process_order(order_xml):
    handler = XMLDataHandler(order_xml)
    order_info = handler.extract_all()
    if "item" in order_info:
        logging.info(f"Processing order for item: {order_info['item']}")
    else:
        logging.warning("No item found in order.")


if __name__ == '__main__':
    xml_input = """
    <order>
        <item>Sample Item</item>
        <quantity>2</quantity>
    </order>
    """

    handler = XMLDataHandler(xml_input)
    print("Root tag:", handler.get_root_tag())
    print("Order as JSON:", handler.to_json())
    process_order(xml_input)
    save_json({'status': 'success'}, 'order_status.json')