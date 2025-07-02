import requests
import logging
import hmac
import hashlib

logger = logging.getLogger(__name__)

def validate_webhook(payload, signature, secret):
    """
    Validate GitHub webhook signature using HMAC-SHA256
    
    Args:
        payload: Raw request payload (bytes)
        signature: Header signature (string)
        secret: Webhook secret (string)
    
    Returns:
        bool: True if signature is valid
    """
    if not signature or not secret:
        logger.error("Missing signature or secret")
        return False
    
    # Create HMAC digest
    digest = hmac.new(
        key=secret.encode('utf-8'),
        msg=payload,
        digestmod=hashlib.sha256
    ).hexdigest()
    
    # Format with algorithm prefix
    expected_signature = f"sha256={digest}"
    
    # Compare signatures
    return hmac.compare_digest(expected_signature, signature)

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
        response = requests.get(diff_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch diff: {str(e)}")
        raise