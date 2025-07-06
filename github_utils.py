import hashlib
import hmac
import json
import logging
import os
import requests
from github import Github, Auth, GithubIntegration

logger = logging.getLogger(__name__)


class GitHubUtils:
    def __init__(self):
        self.app_id = os.getenv("GITHUB_APP_ID")
        self.private_key = os.getenv("GITHUB_PRIVATE_KEY")
        self.webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET')
        self.trigger_team_slug = os.getenv('TRIGGER_TEAM_SLUG', 'ai-review-bots')
        self.github_api_timeout = int(os.getenv("GITHUB_API_TIMEOUT", 10))

        if not self.webhook_secret:
            logger.error("WEBHOOK_SECRET environment variable not set or not provided.")
            raise ValueError("Webhook secret must be provided.")

        if not self.app_id:
            logger.error("GITHUB_APP_ID environment variable not set.")
            raise ValueError("GitHub App ID must be provided.")

        if not self.private_key:
            logger.error("GITHUB_PRIVATE_KEY environment variable not set.")
            raise ValueError("GitHub Private Key must be provided.")

        try:
            auth = Auth.AppAuth(
                app_id=int(self.app_id),
                private_key=self.private_key.replace("\\n", "\n")
            )
            self.integration = GithubIntegration(auth=auth)  # Changed from LegacyGithubIntegration
            logger.info("GithubIntegration initialized successfully.")
        except Exception as e:
            logger.error(f"GithubIntegration initialization failed: {e}", exc_info=True)
            raise ValueError(f"Failed to initialize GitHub Integration: {e}")


    def verify_webhook_signature(self, request_data: bytes, signature: str):
        if not signature:
            raise ValueError("X-Hub-Signature-256 header is missing.")

        sha_name, signature_hex = signature.split('=', 1)
        if sha_name != 'sha256':
            raise ValueError("Signature is not a sha256 signature.")

        mac = hmac.new(self.webhook_secret.encode('utf-8'), msg=request_data, digestmod=hashlib.sha256)
        expected_signature = mac.hexdigest()

        if not hmac.compare_digest(expected_signature, signature_hex):
            raise ValueError("Webhook signature mismatch.")
        logger.debug("Webhook signature verified successfully.")


    def parse_github_webhook(self, request_data: bytes) -> dict:
        payload = json.loads(request_data)
        logger.debug("Webhook payload parsed as JSON.")
        return payload


    def get_installation_token(self, installation_id: int) -> str | None:
        try:
            token = self.integration.get_access_token(installation_id).token
            github_client = Github(token)
            token = github_client.get_user().raw_data['token']
            logger.info(f"Successfully obtained installation token for ID {installation_id}.")
            return token
        except Exception as e:
            logger.error(f"Failed to get installation token for ID {installation_id}: {e}", exc_info=True)
            return None


    def get_pr_diff(self, diff_url: str, access_token: str) -> str | None:
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3.diff",
        }
        try:
            logger.debug(f"Fetching diff from: {diff_url}")
            response = requests.get(diff_url, headers=headers, timeout=self.github_api_timeout)
            response.raise_for_status()
            logger.info(f"Successfully fetched diff from {diff_url}.")
            return response.text
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch diff from {diff_url}: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred while fetching diff from {diff_url}: {e}", exc_info=True)
            return None


    def add_pr_review_comments(self, repo_full_name: str, pr_number: int, summary: str, comments: list,
                               security_issues: list, installation_id: int):
        pull_request = None
        try:
            logger.info(f"Attempting to add review comments for PR #{pr_number} in {repo_full_name}.")
            token = self.integration.get_access_token(installation_id).token
            github_client = Github(token)
            repo = github_client.get_repo(repo_full_name)
            pull_request = repo.get_pull(pr_number)

            body = f"## PR Review Summary ✨\n\n{summary}\n\n"
            if security_issues:
                body += "### Security Issues 🔒\n"
                for issue in security_issues:
                    body += f"- **{issue['file']}:L{issue['line']}**: {issue['issue']}\n"
                body += "\n"

            if comments:
                body += "### General Comments 💬\n"
                for comment_data in comments:
                    body += f"- **{comment_data['file']}:L{comment_data['line']}**: {comment_data['comment']}\n"
                body += "\n"

            if not summary and not security_issues and not comments:
                body += "No specific issues or comments found, but the review process was completed."

            pull_request.create_issue_comment(body)
            logger.info(f"Posted main review summary comment for PR #{pr_number}.")

            if comments or security_issues:
                for comment_data in comments:
                    try:
                        pull_request.create_issue_comment(
                            f"🔍 File `{comment_data['file']}`, Line {comment_data['line']}:\n{comment_data['comment']}"
                        )
                        logger.debug(f"Posted line comment for {comment_data['file']}:L{comment_data['line']}.")
                    except Exception as e:
                        logger.warning(
                            f"Could not post line comment for {comment_data['file']}:L{comment_data['line']}: {e}")

                for issue_data in security_issues:
                    try:
                        pull_request.create_issue_comment(
                            f"🚨 SECURITY ISSUE in `{issue_data['file']}` at line {issue_data['line']}: {issue_data['issue']}"
                        )
                        logger.debug(f"Posted security line comment for {issue_data['file']}:L{issue_data['line']}.")
                    except Exception as e:
                        logger.warning(
                            f"Could not post security line comment for {issue_data['file']}:L{issue_data['line']}: {e}")
            else:
                logger.info("No line comments to post.")

            logger.info(f"Finished adding review comments for PR #{pr_number}.")

        except Exception as e:
            logger.error(f"Failed to add PR review comments for {repo_full_name} PR #{pr_number}: {e}", exc_info=True)
            if pull_request:
                try:
                    pull_request.create_issue_comment(
                        f"## PR Review Commenting Failed ❌\n\n"
                        f"An error occurred while posting review comments: `{e}`\n"
                        f"Please check the application logs for more details."
                    )
                except Exception as comment_e:
                    logger.error(f"Could not post error comment about commenting failure: {comment_e}")


    @staticmethod
    def check_github_api_health() -> str:
        try:
            response = requests.get("https://api.github.com/",
                                    timeout=int(os.getenv("GITHUB_API_HEALTH_CHECK_TIMEOUT", 3)))
            if response.ok:
                return "reachable"
            else:
                return f"unreachable (status: {response.status_code})"
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API health check failed: {e}", exc_info=True)
            return f"unreachable (error: {e})"
        except Exception as e:
            logger.error(f"Unexpected error during GitHub API health check: {e}", exc_info=True)
            return f"unreachable (unexpected error: {e})"
