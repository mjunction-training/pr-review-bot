import json
import os
import logging
from flask import Flask, request, jsonify
from github_utils import GitHubUtils
from mcp_client import MCPClient 

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

try:
    github = GitHubUtils()
except ValueError as e:
    app.logger.error(f"Failed to initialize GitHubAuthenticator: {e}. Exiting.")
    exit(1)

try:
    mcp_client = MCPClient(github_utils=github)
except ValueError as e:
    app.logger.warning(f"Failed to initialize MCPClient: {e}. MCP client will not be initialized.")
    exit(1)


@app.route('/webhook', methods=['POST'])
async def handle_webhook():
    try:
        event=request.headers.get('X-GitHub-Event')
        payload = github.parse_github_webhook(
            request_data=request.data,
            signature=request.headers.get('X-Hub-Signature-256')
        )
    except ValueError as e:
        app.logger.warning(f"Webhook validation failed: {e}")
        return jsonify({"error": "Unauthorized"}), 401
    except json.JSONDecodeError as e:
        app.logger.error(f"Failed to parse webhook payload as JSON: {e}")
        return jsonify({"error": "Bad Request", "message": "Invalid JSON payload"}), 400
    except Exception as e:
        app.logger.error(f"Unexpected error during webhook parsing: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

    app.logger.info(f"Received GitHub event: {event}")
    app.logger.info(f"Requested team: {payload.get('requested_team', {}).get('slug')}")

    if event == "pull_request" and payload.get('action') == "review_requested":
        
        pr_details = github.process_pull_request_review_requested(payload)

        if pr_details is None:
            app.logger.info(f"PR event not relevant or malformed. Ignoring.")
            return jsonify({"status": "ignored", "reason": "PR event not relevant or malformed"}), 200
        
        if not mcp_client:
            app.logger.error("MCP Client not initialized. Cannot send review request.")
            return jsonify({"status": "error", "message": "MCP Client not configured"}), 500

        review_payload = await mcp_client.send_review_request(pr_details)

        if review_payload:
            app.logger.info(f"Received review payload for PR #{pr_details['pr_id']}. Attempting to post comments.")
            try:
                
                github_client = github.get_installation_client(pr_details['installation_id'])
                github.add_pr_review_comments(pr_details['repo'], pr_details['pr_id'], github_client, review_payload)

                return jsonify({"status": "success", "message": "PR review comments posted."}), 200
            except Exception as e:
                app.logger.error(f"Failed to post PR review comments for PR #{pr_details['pr_id']}: {e}")
                return jsonify({"status": "error", "message": f"Failed to post PR review comments: {e}"}), 500
        else:
            app.logger.error(f"Failed to get review payload for PR #{pr_details['pr_id']} from MCP server.")
            return jsonify({"status": "error", "message": "Failed to get review from MCP server"}), 500

    return jsonify({"status": "ignored", "reason": "Not a relevant pull_request event"}), 200

@app.route("/health")
def health_check():
    
    status = {
        "status": "ok",
        "services": {}
    }

    status["services"]["github_api"] = github.check_github_api_health()

    if mcp_client:
        status["services"]["mcp_connection"] = mcp_client.check_mcp_server_health()
    else:
        status["services"]["mcp_connection"] = "not_configured"

    overall_status = "ok"
    for service_status in status["services"].values():
        if "unreachable" in service_status or "error" in service_status:
            overall_status = "warning"
            break
        if service_status == "not_configured":
            overall_status = "warning" 

    status["status"] = overall_status
    return jsonify(status), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=os.getenv('PORT', 5000), debug=False)