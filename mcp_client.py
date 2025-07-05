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
    diff: str
    repo: str
    pr_id: int
    metadata: Dict[str, Any]
    review_prompt_content: str
    summary_prompt_content: str

class CommentClient(BaseModel):
    file: str
    line: int
    comment: str

class SecurityIssueClient(BaseModel):
    file: str
    line: int
    issue: str

class ReviewOutputClient(BaseModel):
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

        # --- IMPORTANT CHANGES HERE ---
        # 1. Initialize the HTTP transport
        self.transport = StreamableHttpTransport(url=self.mcp_url)
        # 2. Pass the transport to the FastMCP client
        self.mcp_client = Client(transport=self.transport)
        # --- END IMPORTANT CHANGES ---

    def load_guidelines(self) -> str:
        try:
            with open("guidelines.md", "r") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load guidelines in mcp_client: {str(e)}")
            return ""

    def build_prompts(self, repo: str, pr_id: int, guidelines: str) -> tuple[str, str]:
        # This method's logic remains the same
        review_prompt = ChatPromptTemplate.from_messages(
            [
                ("system", """You are an AI assistant that reviews code.
                 Your goal is to provide constructive feedback on pull requests, focusing on identifying bugs, security vulnerabilities, performance issues, and maintainability concerns.
                 Adhere to the following guidelines:
                 {guidelines}
                 """),
                ("human", "Review the following code diff for PR #{pr_id} in {repo}:\n\n{diff}\n\nProvide your feedback in a structured JSON format with a summary, line-specific comments, and identified security issues. Each comment should include 'file', 'line', and 'comment'. Each security issue should include 'file', 'line', and 'issue'. For example:\n```json\n{{\n  \"summary\": \"Overall summary of the review.\",\n  \"comments\": [\n    {{\n      \"file\": \"src/main/java/com/example/MyClass.java\",\n      \"line\": 15,\n      \"comment\": \"Consider using a more descriptive variable name.\"\n    }}\n  ],\n  \"security_issues\": [\n    {{\n      \"file\": \"src/main/java/com/example/AuthUtils.java\",\n      \"line\": 30,\n      \"issue\": \"Potential SQL injection vulnerability due to unescaped input.\"\n    }}\n  ]\n}}\n```\n\nIf no comments or security issues are found, return empty arrays for `comments` and `security_issues` respectively.")
            ]
        )

        summary_prompt = ChatPromptTemplate.from_messages(
            [
                ("human", "Generate a concise summary of the following code review comments and security issues:\n\n{comments_text}")
            ]
        )
        return review_prompt.format(guidelines=guidelines, repo=repo, pr_id=pr_id), summary_prompt.format()

    # --- IMPORTANT CHANGE: This method must be async for await call_tool ---
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
                guidelines=guidelines
            )
            
            # Input data remains the same Pydantic model instance
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
            
            # --- IMPORTANT CHANGE: Use fastmcp.client.Client.call_tool method ---
            # This handles JSON-RPC framing, headers, and session ID automatically
            review_payload = await self.mcp_client.call_tool(
                tool_name="pr_review_model", # This must match the name in your @mcp.tool decorator in main.py
                input_data=input_data.model_dump() # Pass the Pydantic model as a dictionary
            )

            logger.info(f"Received review payload for PR #{pr_details['pr_id']} from MCP successfully.")
            return review_payload

        # Use a broader exception catch for FastMCP client errors
        except Exception as e:
            logger.error(f"Failed to get review payload for PR #{pr_details['pr_id']} from MCP server: {str(e)}", exc_info=True)
        return None

    def check_mcp_server_health(self) -> str:
        # This can remain as a direct requests call for a simple health check,
        # as it's not a tool invocation.
        if not self.mcp_url:
            return "not_configured"
        try:
            mcp_response = requests.get(f"{self.mcp_url}/health", timeout=3)
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