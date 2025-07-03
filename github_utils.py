
import os
import requests
import logging
import hmac
import hashlib
from github import Github, Auth 

logger = logging.getLogger(__name__)

# Assuming these are available globally or passed from app.py
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY") # Entire content of .pem file

# Global auth handler for GitHub App
_github_app_auth_handler = None

def get_github_app_installation_client(installation_id):
    """
    Authenticates as a GitHub App installation and returns a PyGithub client.
    """
    global _github_app_auth_handler
    if not _github_app_auth_handler:
        try:
            _github_app_auth_handler = Auth.AppAuth(
                app_id=GITHUB_APP_ID,
                private_key=GITHUB_PRIVATE_KEY,
            )
        except Exception as e:
            logger.error(f"GitHub AppAuth initialization failed: {e}")
            raise
    
    try:
        return Github(auth=_github_app_auth_handler.get_installation_auth(installation_id))
    except Exception as e:
        logger.error(f"Failed to get GitHub App installation client for installation {installation_id}: {e}")
        raise


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

def add_pr_review_comments(repo_full_name, pr_number, installation_id, review_payload):
    """
    Adds review comments (summary, line comments, security issues) to a GitHub PR.

    Args:
        repo_full_name (str): Full name of the repository (e.g., 'owner/repo').
        pr_number (int): The PR number.
        installation_id (int): The GitHub App installation ID.
        review_payload (dict): Dictionary containing 'summary', 'comments', and 'security_issues'.
                               Example: {"summary": "...", "comments": [{"file": "...", "line": ..., "comment": "..."}, ...], "security_issues": ["...", ...]}
    """
    logger.info(f"Attempting to add review comments to {repo_full_name} PR #{pr_number}")
    g = None # Initialize g outside try block for wider scope
    pull_request = None

    try:
        g = get_github_app_installation_client(installation_id)
        repo = g.get_repo(repo_full_name)
        pull_request = repo.get_pull(pr_number)

        # Construct overall PR comment
        pr_comment_body = f"## PR Review by CodeGuardian 🤖\n\n" \
                          f"**Summary:**\n{review_payload.get('summary', 'No summary provided.')}\n\n"

        security_issues = review_payload.get('security_issues', [])
        if security_issues:
            pr_comment_body += "**Potential Security Vulnerabilities:**\n" + \
                               "\n".join([f"- {v}" for v in security_issues]) + "\n\n"
        else:
            pr_comment_body += "**Potential Security Vulnerabilities:** None identified.\n\n"
        
        # Include overall comments if provided (from the original LLM output structure)
        # Assuming the 'summary' in review_payload might also contain overall comments from the LLM
        # If your MCP server provides a separate 'overall_comments' key, use it here.
        # For now, we'll rely on the summary containing the main text.
        
        pull_request.create_issue_comment(pr_comment_body)
        logger.info("Overall PR comment posted.")

        # Add line comments
        line_comments = review_payload.get('comments', [])
        if line_comments:
            latest_commit_id = pull_request.head.sha # Get the latest commit ID of the head branch
            for line_comment in line_comments:
                try:
                    pull_request.create_review_comment(
                        body=line_comment['comment'],
                        commit_id=latest_commit_id,
                        path=line_comment['file'],
                        position=line_comment['line']
                    )
                    logger.info(f"Posted line comment: {line_comment['file']}:{line_comment['line']}")
                except Exception as e:
                    logger.error(f"Error posting line comment for {line_comment['file']}:{line_comment['line']}: {e}")
        else:
            logger.info("No line comments to post.")
        
        logger.info(f"Finished adding review comments for PR #{pr_number}.")

    except Exception as e:
        logger.error(f"Failed to add PR review comments for {repo_full_name} PR #{pr_number}: {e}", exc_info=True)
        # Optionally, post a generic error comment if the client could be obtained
        if g and pull_request:
            try:
                pull_request.create_issue_comment(
                    f"## PR Review Commenting Failed ❌\n\n"
                    f"An error occurred while posting review comments: `{e}`\n"
                    f"Please check the application logs for more details."
                )
            except Exception as comment_e:
                logger.error(f"Could not post error comment about commenting failure: {comment_e}")
