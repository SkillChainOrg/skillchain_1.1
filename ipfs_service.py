# ipfs_service.py
import requests, json, os
import time
from dotenv import load_dotenv


load_dotenv()
PINATA_JWT = os.getenv("PINATA_JWT")

# Gateway priority: Pinata (authenticated) → Cloudflare (public) → IPFS.io (public)
_IPFS_GATEWAYS = [
    "https://gateway.pinata.cloud/ipfs/{cid}",
    "https://cloudflare-ipfs.com/ipfs/{cid}",
    "https://ipfs.io/ipfs/{cid}",
]

def pin_with_retry(metadata: dict, retries: int = 3) -> str:
    last_error = None
    for attempt in range(retries):
        try:
            return pin_certificate_metadata(metadata)
        except Exception as e:
            last_error = e
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # 1s, 2s backoff
    raise RuntimeError(f"IPFS pin failed after {retries} attempts: {last_error}")
def pin_certificate_metadata(metadata: dict) -> str:
    """
    Pins the certificate metadata JSON to IPFS via Pinata.
    Returns the IPFS CID (content identifier).
    NEVER pass PII into metadata — only hashes and non-identifying fields.
    """
    if not PINATA_JWT:
        raise ValueError("PINATA_JWT not set in .env")

    response = requests.post(
        "https://api.pinata.cloud/pinning/pinJSONToIPFS",
        json={
            "pinataContent": metadata,
            "pinataMetadata": {
                "name": f"skillchain-{metadata.get('cert_hash', '')[:16]}"
            }
        },
        headers={
            "Authorization": f"Bearer {PINATA_JWT}",
            "Content-Type": "application/json"
        }
    )
    response.raise_for_status()
    return response.json()["IpfsHash"]  # this is the CID


def fetch_certificate_metadata(cid: str) -> dict:
    """
    Fetch metadata JSON from IPFS.
    Tries Pinata gateway first, then Cloudflare, then ipfs.io.
    Raises RuntimeError only if all gateways fail.
    """
    last_error = None
    for gateway_template in _IPFS_GATEWAYS:
        url = gateway_template.format(cid=cid)
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            last_error = exc
            continue
    raise RuntimeError(
        f"IPFS fetch failed across all gateways for cid={cid}: {last_error}"
    )