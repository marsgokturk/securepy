import os
import json
import shlex
import subprocess
from hashlib import md5


class ConfigManager:
    def __init__(self, config_file):
        self.config_file = config_file
        self.settings = self.load_config()

    def load_config(self):
        try:
            with open(self.config_file, 'r') as file:
                return json.load(file)
        except Exception as e:
            print(f'Error loading config: {e}')
            return {}

    def verify_integrity(self, data, checksum):
        return md5(data.encode()).hexdigest() == checksum


class CommandExecutor:
    def __init__(self, config_manager):
        self.config_manager = config_manager

    def execute_command(self, command):
        try:
            result = subprocess.run(shlex.split(command), check=True, capture_output=True, text=True)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f'Command failed: {e}')

    def run_user_command(self, user_input):
        command = f'echo {shlex.quote(user_input)}'
        self.execute_command(command)


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