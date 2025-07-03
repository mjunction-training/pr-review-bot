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
    payload = request.json # Payload is already parsed by Flask

    app.logger.info(f"Received GitHub event: {event}")

    # Only handle "pull_request" events with "review_requested" action
    if event == "pull_request" and payload.get('action') == "review_requested":
        pull_request = payload.get('pull_request')
        if not pull_request:
            app.logger.error("Missing 'pull_request' object in payload.")
            return jsonify({"status": "ignored", "reason": "missing pull_request object"}), 200

        # Correctly access requested_teams from the pull_request object
        requested_teams = pull_request.get("requested_teams", [])
        
        pr_number = pull_request.get('number')
        repo_full_name = payload['repository']['full_name'] # Repository is at top level

        app.logger.info(f"Received review_requested event for PR #{pr_number} in {repo_full_name}")
        app.logger.info(f"Requested teams: {[team.get('slug') for team in requested_teams]}")

        # Check if the TRIGGER_TEAM_SLUG is in the list of requested teams
        matching_teams = [team for team in requested_teams if team.get("slug") == TRIGGER_TEAM_SLUG]

        if matching_teams:
            # Extract necessary details for the MCP server
            pr_details = {
                "repo": repo_full_name,
                "pr_id": pr_number,
                "diff_url": pull_request.get('diff_url'),
                "commit_sha": pull_request.get('head', {}).get('sha'),
                "installation_id": payload.get('installation', {}).get('id')
            }
            app.logger.info(f"Triggered review by team '{TRIGGER_TEAM_SLUG}' for PR #{pr_details['pr_id']} in {pr_details['repo']}")
            
            # Send to MCP server asynchronously if possible, or handle potential long running task
            # For simplicity, calling directly. In production, consider a task queue.
            send_to_mcp(pr_details, MCP_SERVER_URL)
            
            return jsonify({"status": "team-triggered review started"}), 202
        else:
            app.logger.info(f"No matching team '{TRIGGER_TEAM_SLUG}' in requested reviewers for PR #{pr_number}")
            return jsonify({"status": "team not matched"}), 200

    app.logger.info(f"Ignoring GitHub event type: {event} or action: {payload.get('action')}")
    return jsonify({"status": "ignored"}), 200


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    # Test connectivity to GitHub API
    github_reachable = False
    try:
        response = requests.get("https://api.github.com", timeout=3)
        if response.status_code == 200:
            github_reachable = True
    except requests.exceptions.RequestException as e:
        app.logger.error(f"GitHub API unreachable: {e}")
    
    # You might also want to test connectivity to MCP_SERVER_URL here
    # For now, it's marked as untested.
    mcp_connection_status = "untested" 
    if MCP_SERVER_URL:
        try:
            # A simple GET to MCP_SERVER_URL/health or similar endpoint
            mcp_response = requests.get(f"{MCP_SERVER_URL}/health", timeout=3)
            if mcp_response.status_code == 200:
                mcp_connection_status = "reachable"
            else:
                mcp_connection_status = f"unreachable (status: {mcp_response.status_code})"
        except requests.exceptions.RequestException as e:
            mcp_connection_status = f"unreachable (error: {e})"
        except Exception as e:
            mcp_connection_status = f"unreachable (unexpected error: {e})"


    return jsonify({
        "status": "ok" if github_reachable else "warning",
        "github_api": "reachable" if github_reachable else "unreachable",
        "mcp_connection": mcp_connection_status
    }), 200


if __name__ == '__main__':
    # For local development, ensure environment variables are set
    # e.g., by creating a .env file and using `python-dotenv`
    # from dotenv import load_dotenv
    # load_dotenv()

    if not WEBHOOK_SECRET:
        app.logger.error("GITHUB_WEBHOOK_SECRET environment variable not set.")
        exit(1)
    if not MCP_SERVER_URL:
        app.logger.warning("MCP_SERVER_URL environment variable not set. MCP client calls will likely fail.")

    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
