import json
import logging
import os

from flask import Flask, request, jsonify

from github_utils import GitHubUtils
from mcp_client import MCPClient

app = Flask(__name__)

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
numeric_log_level = getattr(logging, log_level, None)
if not isinstance(numeric_log_level, int):
    raise ValueError(f"Invalid log level: {log_level}")
logging.basicConfig(level=numeric_log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
app.logger.setLevel(numeric_log_level)

app.logger.info(f"Application starting with log level: {log_level}")

try:
    github = GitHubUtils()
    app.logger.info("GitHubUtils initialized successfully.")
except ValueError as e:
    app.logger.error(f"Failed to initialize GitHubAuthenticator: {e}. Exiting.", exc_info=True)
    exit(1)

try:
    mcp_client = MCPClient(github_utils=github)
    app.logger.info("MCPClient initialized successfully.")
except ValueError as e:
    app.logger.error(f"Failed to initialize MCPClient: {e}. Exiting.", exc_info=True)
    exit(1)


@app.route('/webhook', methods=['POST'])
async def handle_webhook():
    app.logger.debug(f"Received webhook request. Headers: {request.headers}")
    try:
        event = request.headers.get('X-GitHub-Event')
        payload = github.parse_github_webhook(
            request_data=request.data,
            signature=request.headers.get('X-Hub-Signature-256')
        )
        app.logger.info(f"Webhook event '{event}' parsed successfully.")
        app.logger.debug(f"Webhook payload: {payload}")

    except json.JSONDecodeError as json_exception:
        app.logger.error(f"Failed to parse webhook payload as JSON: {json_exception}", exc_info=True)
        return jsonify({"error": "Bad Request", "message": "Invalid JSON payload"}), 400
    except ValueError as validation_exception:
        app.logger.warning(f"Webhook validation failed: {validation_exception}", exc_info=True)
        return jsonify({"error": "Unauthorized"}), 401
    except Exception as exception:
        app.logger.error(f"Unexpected error during webhook parsing: {exception}", exc_info=True)
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500

    if event == "pull_request" and payload.get("action") in ["opened", "reopened", "synchronize"]:
        app.logger.info(
            f"Processing pull_request event for PR #{payload['pull_request']['number']} (action: {payload['action']}).")

        requested_teams = payload.get('requested_teams', [])
        requested_team = payload.get('requested_team')

        is_team_requested = any(
            team['slug'] == github.trigger_team_slug for team in requested_teams
        ) or (requested_team and requested_team['slug'] == github.trigger_team_slug)

        if not is_team_requested:
            app.logger.info(
                f"Review not requested for team '{github.trigger_team_slug}'. Ignoring PR #{payload['pull_request']['number']}.")
            return jsonify({"status": "ignored", "reason": "Review not requested for trigger team"}), 200

        pr_details = {
            "pr_id": payload['pull_request']['number'],
            "diff_url": payload['pull_request']['diff_url'],
            "repo_name": payload['repository']['name'],
            "repo_owner": payload['repository']['owner']['login'],
            "installation_id": payload['installation']['id']
        }
        app.logger.debug(f"PR Details extracted: {pr_details}")

        review_output = await mcp_client.send_review_request(pr_details)

        if review_output:
            app.logger.info(f"Received review output from MCP server for PR #{pr_details['pr_id']}.")
            app.logger.debug(
                f"Review Output: Summary='{review_output.summary[:100]}...' Comments={len(review_output.comments)} Security Issues={len(review_output.security_issues)}")
            try:
                github.add_pr_review_comments(
                    repo_full_name=f"{pr_details['repo_owner']}/{pr_details['repo_name']}",
                    pr_number=pr_details['pr_id'],
                    summary=review_output.summary,
                    comments=review_output.comments,
                    security_issues=review_output.security_issues,
                    installation_id=pr_details['installation_id']
                )
                app.logger.info(f"Successfully posted PR review comments for PR #{pr_details['pr_id']}.")
                return jsonify({"status": "success", "message": "PR review comments posted."}), 200
            except Exception as github_post_exception:
                app.logger.error(
                    f"Failed to post PR review comments for PR #{pr_details['pr_id']}: {github_post_exception}",
                    exc_info=True)
                return jsonify(
                    {"status": "error", "message": f"Failed to post PR review comments: {github_post_exception}"}), 500
        else:
            app.logger.error(
                f"Failed to get review payload for PR #{pr_details['pr_id']} from MCP server. No comments will be posted.")
            return jsonify({"status": "error", "message": "Failed to get review from MCP server"}), 500

    app.logger.info(
        f"Webhook event '{event}' with action '{payload.get('action')}' ignored (not a relevant pull_request event for review).")
    return jsonify({"status": "ignored", "reason": "Not a relevant pull_request event"}), 200


@app.route("/health")
def health_check():
    app.logger.debug("Received health check request.")
    status = {
        "status": "ok",
        "services": {}
    }

    github_status = github.check_github_api_health()
    status["services"]["github_api"] = github_status
    app.logger.debug(f"GitHub API health: {github_status}")

    if mcp_client:
        mcp_status = mcp_client.check_mcp_server_health()
        status["services"]["mcp_connection"] = mcp_status
        app.logger.debug(f"MCP server connection health: {mcp_status}")
    else:
        status["services"]["mcp_connection"] = "not_configured"
        app.logger.warning("MCPClient not initialized, MCP connection health not checked.")

    overall_status = "ok"
    for service_name, service_status in status["services"].items():
        if "unreachable" in service_status or "error" in service_status:
            overall_status = "warning"
            app.logger.warning(f"Health check warning: Service '{service_name}' status is '{service_status}'.")
            break
        if service_status == "not_configured":
            overall_status = "warning"
            app.logger.warning(f"Health check warning: Service '{service_name}' is not configured.")

    status["status"] = overall_status
    app.logger.info(f"Overall health status: {overall_status}")
    app.logger.debug(f"Full health status response: {status}")
    return jsonify(status)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    app.logger.info(f"Starting Flask app on port {port}")
    app.run(host="0.0.0.0", port=port, debug=(numeric_log_level <= logging.DEBUG))