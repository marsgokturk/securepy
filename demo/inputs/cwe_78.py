import subprocess
import sys


def run_backup(backup_type):
    if not backup_type:
        raise ValueError("Invalid backup type specified.")

    try:
        command = f"/path/to/backup_script.sh {backup_type}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            print("Backup completed successfully.")
            print(result.stdout)
        else:
            print("An error occurred during backup.")
            print(result.stderr)

    except Exception as e:
        print(f"Exception occurred: {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python backup_tool.py <backup_type>")
        sys.exit(1)

    backup_type = sys.argv[1]
    run_backup(backup_type)

if __name__ == "__main__":
    main()