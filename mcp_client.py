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

        # --- IMPORTANT NEW CHANGE HERE ---
        # Ensure the URL points to the FastMCP RPC endpoint, typically /mcp
        if not self.mcp_url.endswith('/mcp'):
            self.mcp_url = f"{self.mcp_url.rstrip('/')}/mcp"
        # --- END IMPORTANT NEW CHANGE --
        
        self.transport = StreamableHttpTransport(url=self.mcp_url)
        self.mcp_client = Client(transport=self.transport)

    def load_guidelines(self) -> str:
        try:
            with open("guidelines.md", "r") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load guidelines in mcp_client: {str(e)}")
            return ""

    # MODIFIED: Add 'diff' as a parameter to build_prompts
    def build_prompts(self, repo: str, pr_id: int, guidelines: str, diff: str) -> tuple[str, str]:
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

        summary_prompt_template_obj = ChatPromptTemplate.from_messages( # Renamed variable for clarity
            [
                ("human", "Generate a concise summary of the following code review comments and security issues:\n\n{comments_text}")
            ]
        )
        
        # Format the review prompt with all its required variables
        review_prompt_output = review_prompt.format(
            guidelines=guidelines,
            repo=repo,
            pr_id=pr_id,
            diff=diff # <-- ADDED 'diff' here
        )
        
        # Get the raw template string for the summary prompt, as it will be formatted later
        summary_prompt_output = summary_prompt_template_obj.messages[0].prompt.template

        return review_prompt_output, summary_prompt_output

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
            
            review_payload = None # Initialize review_payload outside the async with block

            # --- IMPORTANT CHANGE: Use async with context manager for self.mcp_client ---
            async with self.mcp_client as client: # <--- ADDED context manager
                review_payload = await client.call_tool( # <--- Call method on 'client' from context
                    name="pr_review_model",
                    arguments=input_data.model_dump(),
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