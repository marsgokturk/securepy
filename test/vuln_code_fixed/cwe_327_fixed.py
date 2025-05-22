import os
import json
import subprocess
from hashlib import sha256

class ConfigManager:
    def __init__(self, config_file):
        self.config_file = config_file
        self.settings = self.load_config()

    def load_config(self):
        try:
            if not os.path.isfile(self.config_file):
                raise FileNotFoundError(f'Config file {self.config_file} not found.')
            with open(self.config_file, 'r') as file:
                return json.load(file)
        except (IOError, json.JSONDecodeError) as e:
            print(f'Error loading config: {e}')
            return {}

    def verify_integrity(self, data, checksum):
        return sha256(data.encode()).hexdigest() == checksum

    def get_setting(self, key):
        return self.settings.get(key)

class CommandExecutor:
    def __init__(self, config_manager):
        self.config_manager = config_manager

    def execute_command(self, command_args):
        try:
            result = subprocess.run(command_args, check=True, capture_output=True, text=True)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f'Command failed: {e}')

    def run_user_command(self, user_input):
        self.execute_command(['echo', user_input])

def main():
    config_manager = ConfigManager('data.json')
    data = config_manager.get_setting('data')
    checksum = config_manager.get_setting('checksum')
    if data and checksum and config_manager.verify_integrity(data, checksum):
        print("Data integrity verified. Proceeding to command execution.")
        command_executor = CommandExecutor(config_manager)
        user_input = input('Enter text to echo: ')
        command_executor.run_user_command(user_input)
    else:
        print("Data integrity check failed or data not found. Aborting operation.")

if __name__ == '__main__':
    main()