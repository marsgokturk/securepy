import os
import yaml

def load_user_config(config_path):
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file {config_path} does not exist.")
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

def save_user_config(config, config_path):
    with open(config_path, 'w') as file:
        yaml.safe_dump(config, file, default_flow_style=False)

def print_config_summary(config):
    print("Configuration Summary:")
    for section, settings in config.items():
        print(f"Section: {section}")
        for key, value in settings.items():
            print(f" {key}: {value}")

def get_default_config():
    return {
        "network": {
            "host": "127.0.0.1",
            "port": 8080
        },
        "auth": {
            "enabled": True,
            "methods": ["password", "token"]
        },
        "features": {
            "dark_mode": False,
            "logging": True
        }
    }

def main():
    import argparse
    parser = argparse.ArgumentParser(description="User Config Manager")
    parser.add_argument("--config", help="Path to user configuration YAML file.")
    parser.add_argument("--dump-default", action="store_true", help="Dump default config to file and exit.")
    args = parser.parse_args()

    if args.dump_default:
        default_config = get_default_config()
        save_user_config(default_config, "default_config.yaml")
        print("Default configuration written to default_config.yaml")
        return

    if args.config:
        config = load_user_config(args.config)
        print_config_summary(config)
    else:
        print("No configuration file specified. Use --config <file.yaml> to load a config.")

if __name__ == "__main__":
    main()