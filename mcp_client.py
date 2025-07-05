import os
import requests
import logging
from github_utils import GitHubUtils
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from fastmcp.client import Client
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

class MCPClient:
    def __init__(self, github_utils: GitHubUtils):
        self.github_utils = github_utils
        self.mcp_url = os.getenv('MCP_SERVER_URL')
        if not self.mcp_url:
            logger.error("MCP_SERVER_URL environment variable not set.")
            raise ValueError("MCP_SERVER_URL must be provided or set as an environment variable.")

    def load_guidelines(self) -> str:
        try:
            with open("guidelines.md", "r") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load guidelines in mcp_client: {str(e)}")
            return ""

    def build_prompts(self, repo: str, pr_id: int, guidelines: str) -> tuple[str, str]:
        parser = StrOutputParser()

        review_prompt_template = ChatPromptTemplate.from_messages([
            ("system", (
                "<s>[INST] <<SYS>>\n"
                "You are an expert code reviewer. Follow these guidelines:\n"
                "{guidelines}\n"
                "Review tasks:\n"
                "1. Summarize changes in this diff chunk\n"
                "2. Add line comments (format: FILE:LINE: COMMENT)\n"
                "3. Flag security vulnerabilities (format: SECURITY:FILE:LINE: ISSUE)\n"
                "<</SYS>>"
            )),
            ("human", "{diff_chunk}")
        ])

        review_prompt_content = parser.parse(review_prompt_template.format_messages(
            guidelines=guidelines,
            diff_chunk=""
        )[0].content)

        summary_prompt_template = ChatPromptTemplate.from_messages([
            ("human", f"Generate concise summary of PR #{pr_id} in {repo} based on these comments:\n\n{{comments_text}}")
        ])

        summary_prompt_content = parser.parse(summary_prompt_template.format_messages(
            pr_id=pr_id,
            repo=repo,
            comments_text=""
        )[0].content)

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
                guidelines=guidelines
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
            
            logger.info(f"Sending PR #{pr_details['pr_id']} to MCP server at {self.mcp_url} for review.")

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }

            response = requests.post(
                f"{self.mcp_url}/mcp/pr_review_model",
                json=input_data.model_dump(),
                headers=headers,
                timeout=600
            )
            response.raise_for_status()
            review_payload = response.json()

            logger.info(f"Received review payload for PR #{pr_details['pr_id']} from MCP successfully.")
            return review_payload

        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP error sending to MCP or receiving response: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to send to MCP or process response: {str(e)}")
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