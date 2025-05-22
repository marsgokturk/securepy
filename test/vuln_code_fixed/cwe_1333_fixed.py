import re

sentence_pattern = re.compile(r'^((?=(\w+))\2\s?)*$')

def is_valid_sentence(input_text):
    """
    Check if the input text is a "valid sentence" using a regular expression.

    Args:
        input_text (str): The input text to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    return bool(sentence_pattern.search(input_text))

def process_text_file(file_path):
    """
    Process a text file where each line is validated as a sentence.

    Args:
        file_path (str): The path to the text file to process.

    Returns:
        list: A list of booleans indicating which lines are valid sentences.
    """
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if is_valid_sentence(line.strip()):
                    results.append(True)
                else:
                    results.append(False)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        raise
    except Exception as e:
        print(f"An error occurred: {e}")
        raise
    return results
