import os
import logging
from flask import Flask, request, jsonify
from github_utils import validate_webhook, get_pr_diff
from mcp_client import send_to_mcp

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
MCP_SERVER_URL = os.getenv('MCP_SERVER_URL')

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    # Validate signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not validate_webhook(request.data, signature, WEBHOOK_SECRET):
        app.logger.warning("Invalid webhook signature")
        return jsonify({"error": "Unauthorized"}), 401

    event = request.headers.get('X-GitHub-Event')
    payload = request.json

    # Process only PR events
    if event == "pull_request" and payload['action'] in ['opened', 'reopened', 'synchronize']:
        pr_details = {
            "repo": payload['repository']['full_name'],
            "pr_id": payload['pull_request']['number'],
            "diff_url": payload['pull_request']['diff_url'],
            "commit_sha": payload['pull_request']['head']['sha'],
            "installation_id": payload['installation']['id']
        }
        app.logger.info(f"Processing PR #{pr_details['pr_id']} in {pr_details['repo']}")

        # Queue processing
        send_to_mcp(pr_details, MCP_SERVER_URL)
        return jsonify({"status": "processing started"}), 202

    return jsonify({"status": "ignored"}), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)