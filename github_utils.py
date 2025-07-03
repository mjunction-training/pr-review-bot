import requests
import logging
import hmac
import hashlib

logger = logging.getLogger(__name__)


def validate_webhook(payload, signature, secret):
    """
    Validate GitHub webhook signature using HMAC-SHA256.

    Args:
        payload (bytes): Raw request payload.
        signature (str): The value of the 'X-Hub-Signature-256' header (e.g., 'sha256=HEX_DIGEST').
        secret (str): The webhook secret configured in your GitHub App.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    if not signature or not secret:
        print("Error: Missing signature header or webhook secret.")
        return False

    # GitHub signature format is 'sha256=HEX_DIGEST'
    try:
        sha_name, hex_digest = signature.split('=')
    except ValueError:
        print("Error: X-Hub-Signature-256 header is not in the expected 'sha256=HEX_DIGEST' format.")
        return False

    if sha_name != 'sha256':
        print(f"Error: Signature algorithm is '{sha_name}', expected 'sha256'.")
        return False

    # Calculate the HMAC digest of the payload
    mac = hmac.new(secret.encode('utf-8'), msg=payload, digestmod=hashlib.sha256)
    calculated_digest = mac.hexdigest()

    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
    return hmac.compare_digest(calculated_digest, hex_digest)

def get_pr_diff(diff_url, access_token):
    """
    Fetch PR diff content from GitHub
    
    Args:
        diff_url: GitHub API diff URL
        access_token: Installation access token
    
    Returns:
        str: Diff content
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github.v3.diff",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    try:
        response = requests.get(diff_url, headers=headers, timeout=120)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch diff: {str(e)}")
        raise