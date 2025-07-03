import os
import requests
import logging
from flask import Flask, request, jsonify
from github_utils import validate_webhook, get_pr_diff
from mcp_client import send_to_mcp

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
MCP_SERVER_URL = os.getenv('MCP_SERVER_URL')
TRIGGER_TEAM_SLUG = os.getenv('TRIGGER_TEAM_SLUG', 'ai-review-bots')  # Set your team slug here or via env

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    # Validate signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not validate_webhook(request.data, signature, WEBHOOK_SECRET):
        app.logger.warning("Invalid webhook signature")
        return jsonify({"error": "Unauthorized"}), 401

    event = request.headers.get('X-GitHub-Event')
    payload = request.json

    # Only handle when team reviewers are added to a PR
    if event == "pull_request" and payload.get('action') == "requested_reviewers":
        requested_teams = payload.get("requested_teams", [])
        app.logger.error(f"Received requested_reviewers event for PR #{payload['pull_request']['number']} in {payload['repository']['full_name']}")
        app.logger.error(f"Requested reviewers: {requested_teams}")
        matching_teams = [team for team in requested_teams if team.get("slug") == TRIGGER_TEAM_SLUG]

        if matching_teams:
            pr_details = {
                "repo": payload['repository']['full_name'],
                "pr_id": payload['pull_request']['number'],
                "diff_url": payload['pull_request']['diff_url'],
                "commit_sha": payload['pull_request']['head']['sha'],
                "installation_id": payload['installation']['id']
            }
            app.logger.info(f"Triggered review by team '{TRIGGER_TEAM_SLUG}' for PR #{pr_details['pr_id']} in {pr_details['repo']}")
            send_to_mcp(pr_details, MCP_SERVER_URL)
            return jsonify({"status": "team-triggered review started"}), 202
        else:
            app.logger.info(f"No matching team '{TRIGGER_TEAM_SLUG}' in requested reviewers")
            return jsonify({"status": "team not matched"}), 200

    return jsonify({"status": "ignored"}), 200


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    # Test connectivity to GitHub API
    try:
        response = requests.get("https://api.github.com", timeout=3)
        if response.status_code == 200:
            return jsonify({
                "status": "ok",
                "github_api": "reachable",
                "mcp_connection": "untested"
            }), 200
    except:
        pass
    
    return jsonify({
        "status": "warning",
        "github_api": "unreachable",
        "mcp_connection": "untested"
    }), 200


if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port)