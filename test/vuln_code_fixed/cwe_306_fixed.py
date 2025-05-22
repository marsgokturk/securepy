import subprocess


class UserManager:
    def __init__(self):
        self.users = {}

    def add_user(self, username, command):
        if username in self.users:
            raise ValueError("User already exists.")
        self.users[username] = command
        print(f"User {username} added with command: {command}")

    def execute_command(self, username):
        if username not in self.users:
            raise ValueError("User not found.")
        command = self.users[username]
        print(f"Executing command for {username}: {command}")

        try:
            subprocess.run(command, shell=False, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: {e}")


class CommandLineInterface:
    def __init__(self):
        self.user_manager = UserManager()

    def run(self):
        while True:
            action = input("Enter action (add/execute/exit): ").strip().lower()
            if action == 'add':
                username = input("Enter username: ").strip()
                command = input("Enter command: ").strip()
                self.user_manager.add_user(username, command)
            elif action == 'execute':
                username = input("Enter username to execute command: ").strip()
                self.user_manager.execute_command(username)
            elif action == 'exit':
                print("Exiting...")
                break
            else:
                print("Invalid action. Please try again.")


if __name__ == '__main__':
    cli = CommandLineInterface()
    cli.run()