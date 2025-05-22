import json
import logging

logging.basicConfig(level=logging.INFO)

def get_user_data(user_id):
    user_db = {
        "1": {"name": "Alice", "balance": 1000.0},
        "2": {"name": "Bob", "balance": 500.0},
    }
    return user_db.get(str(user_id), None)

def get_discount_code_value(code):
    discount_db = {
        "SUMMER10": 10,
        "WELCOME20": 20,
        "VIP50": 50,
    }
    return discount_db.get(code, 0)

def apply_discount(user_id, discount_code):
    user_data = get_user_data(user_id)
    if not user_data:
        logging.error("User not found.")
        return

    discount = get_discount_code_value(discount_code)
    if discount <= 0:
        logging.error("Invalid discount code.")
        return

    new_balance = user_data["balance"] - ((discount / 100) * user_data["balance"])
    if new_balance < 0:
        logging.error("Discount is too large, resulting in negative balance.")
        return

    logging.info(f"Discount of {discount}% applied. New balance for {user_data['name']}: {new_balance:.2f}")

def validate_input(data):
    if not isinstance(data, dict):
        raise ValueError("Input data must be a dictionary.")
    if 'user_id' not in data or 'discount_code' not in data:
        raise KeyError("Missing required fields.")
    if not isinstance(data['user_id'], str) or not data['user_id'].isdigit():
        raise ValueError("User ID must be a valid string of digits.")
    if not isinstance(data['discount_code'], str):
        raise ValueError("Discount code must be a valid string.")

def main():
    user_input = input("Enter user data in JSON format: ")
    try:
        data = json.loads(user_input)
        validate_input(data)
        user_id = data['user_id']
        discount_code = data['discount_code']
        apply_discount(user_id, discount_code)
    except json.JSONDecodeError:
        logging.error("Invalid input format.")
    except KeyError as e:
        logging.error(f"Missing expected field {e}.")
    except ValueError as e:
        logging.error(str(e))

if __name__ == "__main__":
    main()