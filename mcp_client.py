import os
import requests
import logging
from github_utils import GitHubUtils
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport
from pydantic import BaseModel
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ReviewInputClient(BaseModel):
    """Schema for the input payload to the PR review model on the client side."""
    diff: str
    repo: str
    pr_id: int
    metadata: Dict[str, Any]
    review_prompt_content: str
    summary_prompt_content: str

class CommentClient(BaseModel):
    """Schema for a single line comment on the client side."""
    file: str
    line: int
    comment: str

class SecurityIssueClient(BaseModel):
    """Schema for a single security issue on the client side."""
    file: str
    line: int
    issue: str

class ReviewOutputClient(BaseModel):
    """Schema for the output payload from the PR review model on the client side."""
    summary: str
    comments: List[CommentClient]
    security_issues: List[SecurityIssueClient]
# --- End BaseModel classes ---

class MCPClient:
    def __init__(self, github_utils: GitHubUtils):
        self.github_utils = github_utils
        self.mcp_url = os.getenv('MCP_SERVER_URL')
        if not self.mcp_url:
            logger.error("MCP_SERVER_URL environment variable not set.")
            raise ValueError("MCP_SERVER_URL must be provided or set as an environment variable.")

        # Ensure mcp_url explicitly ends with '/mcp/'
        self.mcp_url = self.mcp_url.rstrip('/') # Remove any existing trailing slash
        if not self.mcp_url.endswith('/mcp'):
            self.mcp_url = f"{self.mcp_url}/mcp" # Ensure it has /mcp
        self.mcp_url = f"{self.mcp_url}/" # Explicitly add the trailing slash
        
        self.transport = StreamableHttpTransport(url=self.mcp_url)
        self.mcp_client = Client(transport=self.transport)

    def load_guidelines(self) -> str:
        try:
            with open("guidelines.md", "r") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load guidelines in mcp_client: {str(e)}")
            return ""

    def build_prompts(self, repo: str, pr_id: int, guidelines: str, diff: str) -> tuple[str, str]:
        # --- IMPORTANT CHANGE: Escaped curly braces in JSON example ---
        review_prompt_content = f"""
            You are an AI assistant that reviews GitHub Pull Requests.
            Your task is to provide a comprehensive code review based on the provided guidelines and code changes.
            Focus on identifying potential bugs, security vulnerabilities, performance issues, and maintainability concerns.
            Provide actionable suggestions and code examples where appropriate.

            <review_guidelines>
            {guidelines}
            </review_guidelines>

            <pr_details>
            Repository: {repo}
            Pull Request ID: {pr_id}
            </pr_details>

            <diff>
            {diff}
            </diff>

            Please provide your review in the following JSON format:
            {{{{
                "summary": "A concise summary of the overall review.",
                "comments": [
                    {{{{
                        "file": "path/to/file.py",
                        "line": 123,
                        "comment": "Your detailed comment for this line."
                    }}}}
                ],
                "security_issues": [
                    {{{{
                        "file": "path/to/file.py",
                        "line": 45,
                        "issue": "Description of the security vulnerability."
                    }}}}
                ]
            }}}}
            Ensure the JSON is valid and complete.
            """
        # --- END IMPORTANT CHANGE ---

        summary_prompt_content = f"""
            Summarize the review comments for the following pull request.
            The comments and security issues to be summarized will be provided after this instruction.
            """
        return review_prompt_content, summary_prompt_content
    

    async def send_review_request(self, pr_details: dict) -> dict | None:
        try:
            installation_id = pr_details['installation_id']
            access_token = self.github_utils.get_installation_token(installation_id)

            if not access_token:
                logger.error("No access token available for fetching diff.")
                return None
            
            diff_content = self.github_utils.get_pr_diff(pr_details['diff_url'], access_token)
            guidelines = self.load_guidelines()

            review_prompt_content, summary_prompt_content = self.build_prompts(
                repo=pr_details['repo'],
                pr_id=pr_details['pr_id'],
                guidelines=guidelines,
                diff=diff_content
            )
            
            input_data = ReviewInputClient(
                diff=diff_content,
                repo=pr_details['repo'],
                pr_id=pr_details['pr_id'],
                metadata={
                    "commit_sha": pr_details['commit_sha'],
                    "installation_id": installation_id
                },
                review_prompt_content=review_prompt_content,
                summary_prompt_content=summary_prompt_content
            )
            
            logger.info(f"Attempting to send PR #{pr_details['pr_id']} to MCP server using fastmcp.client.")
            
            review_payload = None 

            async with self.mcp_client as client: 
                review_payload = await client.call_tool(
                    name="pr_review_model",
                    arguments={"input_data": input_data.model_dump()},
                    timeout=600
                )

            logger.info(f"Received review payload for PR #{pr_details['pr_id']} from MCP successfully.")
            return review_payload

        except Exception as e:
            logger.error(f"Failed to get review payload for PR #{pr_details['pr_id']} from MCP server: {str(e)}", exc_info=True)
        return None

    def check_mcp_server_health(self) -> str:
        if not self.mcp_url:
            return "not_configured"
        try:
            # Corrected health check URL path
            health_url = self.mcp_url.replace("/mcp/", "/health")
            mcp_response = requests.get(health_url, timeout=3) 
            if mcp_response.status_code == 200:
                return "reachable"
            else:
                return f"unreachable (status: {mcp_response.status_code})"
        except requests.exceptions.RequestException as e:
            logger.error(f"MCP server health check failed: {e}")
            return f"unreachable (error: {e})"
        except Exception as e:
            logger.error(f"Unexpected error during MCP server health check: {e}")
            return f"unreachable (unexpected error: {e})"