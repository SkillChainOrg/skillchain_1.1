import os
import requests


VAULT_SERVICE_URL = os.getenv("VAULT_SERVICE_URL")

requests.get(f"{VAULT_SERVICE_URL}/health")
def store_artisan_secret(artisan_id, secret):
    response = requests.post(
        f"{VAULT_SERVICE_URL}/store-test-secret",
        json={
            "artisan_id": artisan_id,
            "secret": secret
        },
        timeout=5
    )

    response.raise_for_status()

    return response.json()


def load_artisan_secret(artisan_id):
    response = requests.get(
        f"{VAULT_SERVICE_URL}/load-test-secret/{artisan_id}",
        timeout=5
    )

    response.raise_for_status()

    return response.json()