import os
import json
import requests
import logging
import jwt
import time
from github_utils import get_pr_diff

logger = logging.getLogger(__name__)

class GitHubAppAuth:
    """Handles GitHub App authentication and token generation"""
    _tokens = {}  # Cache: {installation_id: (token, expiry)}

    def __init__(self):
        self.app_id = os.getenv('GITHUB_APP_ID')
        self.private_key = os.getenv('GITHUB_PRIVATE_KEY')
        if not self.private_key or not self.app_id:
            logger.error("Missing GitHub App credentials")
            raise ValueError("GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be set")

        # Decode base64 if needed
        if "-----BEGIN RSA PRIVATE KEY-----" not in self.private_key:
            try:
                import base64
                self.private_key = base64.b64decode(self.private_key).decode('utf-8')
            except:
                logger.error("Failed to decode private key")

    def create_jwt(self):
        """Generate JWT for GitHub App authentication"""
        payload = {
            'iat': int(time.time()),
            'exp': int(time.time()) + 600,  # 10 minutes max
            'iss': self.app_id
        }
        return jwt.encode(payload, self.private_key, algorithm='RS256')

    def get_installation_token(self, installation_id):
        """Get installation access token with caching"""
        # Check cache
        if installation_id in self._tokens:
            token, expiry = self._tokens[installation_id]
            if time.time() < expiry - 60:  # 1 minute buffer
                return token

        # Request new token
        jwt_token = self.create_jwt()
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        
        try:
            response = requests.post(url, headers=headers, timeout=5)
            response.raise_for_status()
            token_data = response.json()
            token = token_data['token']
            # Expiry has buffer (GitHub tokens last 1 hour)
            expiry = time.time() + 3500  # 58 minutes
            
            # Update cache
            self._tokens[installation_id] = (token, expiry)
            logger.info(f"Generated new installation token for {installation_id}")
            return token
        except Exception as e:
            logger.error(f"Failed to get installation token: {str(e)}")
            raise

# Global auth handler
_auth_handler = None

def get_installation_token(installation_id):
    """Public function to get installation token"""
    global _auth_handler
    if not _auth_handler:
        try:
            _auth_handler = GitHubAppAuth()
        except Exception as e:
            logger.error(f"Auth handler init failed: {str(e)}")
            return None
    
    return _auth_handler.get_installation_token(installation_id)

def send_to_mcp(pr_details, mcp_url):
    """Send PR data to MCP server for review"""
    try:
        installation_id = pr_details['installation_id']
        access_token = get_installation_token(installation_id)
        
        if not access_token:
            logger.error("No access token available")
            return False
        
        # Get PR diff
        diff_content = get_pr_diff(pr_details['diff_url'], access_token)
        
        # Prepare payload
        payload = {
            "repo": pr_details['repo'],
            "pr_id": pr_details['pr_id'],
            "diff": diff_content,
            "metadata": {
                "commit_sha": pr_details['commit_sha'],
                "installation_id": installation_id
            }
        }
        
        # Send to MCP server
        response = requests.post(
            f"{mcp_url}/review",
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        logger.info(f"Sent PR #{pr_details['pr_id']} to MCP successfully")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP error sending to MCP: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to send to MCP: {str(e)}")
    return False