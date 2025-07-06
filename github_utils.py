import hashlib
import hmac
import json
import logging
import os

import requests
from github import Github, Auth
from github import GithubIntegration as LegacyGithubIntegration

logger = logging.getLogger(__name__)


class GitHubUtils:
    def __init__(self):
        self.app_id = os.getenv("GITHUB_APP_ID")
        self.private_key = os.getenv("GITHUB_PRIVATE_KEY")
        self.webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET')
        self.trigger_team_slug = os.getenv('TRIGGER_TEAM_SLUG', 'ai-review-bots')

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
            self.integration = LegacyGithubIntegration(auth=auth)
        except Exception as e:
            logger.error(f"GithubIntegration init failed: {e}")
            raise

    def get_installation_token(self, installation_id: int) -> str:
        try:
            access_token = self.integration.get_access_token(installation_id).token
            return access_token
        except Exception as e:
            logger.error(f"Failed to get installation token for installation {installation_id}: {e}")
            raise RuntimeError(f"Could not retrieve installation token: {e}")

    def get_installation_client(self, installation_id: int) -> Github:
        try:
            token = self.get_installation_token(installation_id)
            return Github(login_or_token=token)
        except Exception as e:
            logger.error(f"Failed to create installation client: {e}")
            raise

    def validate_webhook_signature(self, payload: bytes, signature: str) -> bool:
        if not signature or not self.webhook_secret:
            logger.warning("Error: Missing signature header or webhook secret.")
            return False

        try:
            sha_name, hex_digest = signature.split('=')
        except ValueError:
            logger.warning("Error: X-Hub-Signature-256 header is not in the expected 'sha256=HEX_DIGEST' format.")
            return False

        if sha_name != 'sha256':
            logger.warning(f"Error: Signature algorithm is '{sha_name}', expected 'sha256'.")
            return False

        mac = hmac.new(self.webhook_secret.encode('utf-8'), msg=payload, digestmod=hashlib.sha256)
        calculated_digest = mac.hexdigest()

        return hmac.compare_digest(calculated_digest, hex_digest)

    def parse_github_webhook(self, request_data: bytes, signature: str) -> dict:
        if not self.validate_webhook_signature(request_data, signature):
            logger.warning("Invalid webhook signature")
            raise ValueError("Invalid webhook signature")

        payload = json.loads(request_data)
        return payload

    def process_pull_request_review_requested(self, payload: dict) -> dict | None:
        pull_request = payload.get('pull_request')
        logger.info(f"Received GitHub event: pull_request {pull_request}")
        if not pull_request:
            logger.error("Missing 'pull_request' object in payload.")
            return None

        repo_full_name = pull_request['base']['repo']['full_name']
        pr_number = pull_request['number']
        diff_url = pull_request['diff_url']
        commit_sha = pull_request['head']['sha']
        installation_id = payload['installation']['id']

        # FIXED: Check both requested_teams (for safety) and requested_team (actual)
        requested_teams = payload.get('requested_teams', [])
        requested_team = payload.get('requested_team')  # single object

        is_team_requested = any(
            team['slug'] == self.trigger_team_slug for team in requested_teams
        ) or (requested_team and requested_team['slug'] == self.trigger_team_slug)

        if not is_team_requested:
            logger.info(f"Review not requested for team '{self.trigger_team_slug}'. Ignoring PR #{pr_number}.")
            return None

        logger.info(f"Review requested for PR #{pr_number} in {repo_full_name} by team '{self.trigger_team_slug}'.")

        return {
            "repo": repo_full_name,
            "pr_id": pr_number,
            "diff_url": diff_url,
            "commit_sha": commit_sha,
            "installation_id": installation_id
        }

    @staticmethod
    def get_pr_diff(diff_url: str, access_token: str) -> str:
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
            logger.error(f"Failed to fetch diff from {diff_url}: {str(e)}")
            raise

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
            response = requests.get("https://api.github.com/", timeout=3)
            if response.ok:
                return "reachable"
            else:
                return f"unreachable (status: {response.status_code})"
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API health check failed: {e}")
            return f"unreachable (error: {e})"
        except Exception as e:
            logger.error(f"Unexpected error during GitHub API health check: {e}")
            return f"unreachable (unexpected error: {e})"