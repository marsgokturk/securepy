import subprocess


class User:
    def __init__(self, username):
        self.username = username

    def get_username(self):
        return self.username


class CommandExecutor:
    def __init__(self, user):
        self.user = user

    def execute_command(self, command):
        allowed_commands = ['ls', 'whoami', 'date']  # Example commands

        if command.split()[0] in allowed_commands:
            try:
                result = subprocess.run(command, shell=False, check=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                print(result.stdout.decode())
            except subprocess.CalledProcessError as e:
                print(f"Error executing command: {e.stderr.decode()}")
        else:
            print("Command not allowed!")


def main():
    user_input = input("Enter your username: ")
    user = User(user_input)
    print(f"Welcome, {user.get_username()}!")
    command_executor = CommandExecutor(user)

    while True:
        command = input("Enter a command to execute (or 'exit' to quit): ")
        if command.lower() == 'exit':
            break
        command_executor.execute_command(command)


if __name__ == '__main__':
    main()