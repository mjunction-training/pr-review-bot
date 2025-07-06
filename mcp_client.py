import json
import logging
import os
import re
from typing import List, Dict, Any

import requests
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel

from github_utils import GitHubUtils

logger = logging.getLogger(__name__)


class HFPassthroughInputClient(BaseModel):
    model_name: str
    inputs: str


class HFPassthroughOutputClient(BaseModel):
    response_data: Dict[str, Any]


class Comment(BaseModel):
    file: str
    line: int
    comment: str


class SecurityIssue(BaseModel):
    file: str
    line: int
    issue: str


class ParsedReviewOutput(BaseModel):
    summary: str
    comments: List[Comment]
    security_issues: List[SecurityIssue]


class MCPClient:
    def __init__(self, github_utils: GitHubUtils):
        self.github_utils = github_utils
        self.mcp_url = os.getenv('MCP_SERVER_URL')
        self.mcp_client_timeout = int(os.getenv("MCP_CLIENT_TIMEOUT", 600))
        if not self.mcp_url:
            logger.error("MCP_SERVER_URL environment variable not set.")
            raise ValueError("MCP_SERVER_URL must be provided or set as an environment variable.")

        self.mcp_url = self.mcp_url.rstrip('/')
        if not self.mcp_url.endswith('/mcp'):
            self.mcp_url = f"{self.mcp_url}/mcp"
        self.mcp_url = f"{self.mcp_url}/"

        self.transport = StreamableHttpTransport(url=self.mcp_url)
        self.mcp_client = Client(transport=self.transport)


    @staticmethod
    def load_guidelines() -> str:
        try:
            with open("guidelines.md", "r") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load guidelines in mcp_client: {str(e)}", exc_info=True)
            return ""


    @staticmethod
    def build_review_prompt(repo: str, pr_id: int, guidelines: str, diff: str) -> str:
        review_prompt_content = """
            You are a expert code reviewer who reviews GitHub Pull Requests.
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

            Please provide your review in the following format:
            For regular comments: <file>:<line number>:<comment>
            For security issues: SECURITY:<file>:<line number>:<issue description>
            """

        template = ChatPromptTemplate([
            ("system", review_prompt_content)
        ])

        review_prompt_template = template.invoke(
            {
                "guidelines": guidelines,
                "repo": repo,
                "pr_id": pr_id,
                "diff": diff
            }
        )

        return StrOutputParser().parse(review_prompt_template.to_messages()[0].content)


    @staticmethod
    def build_summary_prompt(review_raw_text: str) -> str:
        summary_prompt_content = """
            Summarize the review comments for the following pull request.
            The comments and security issues to be summarized are provided below.
            """

        final_summary_prompt_text = """
            {summary_prompt_content}

            <review_raw_text>
            {review_raw_text}
            </review_raw_text>
            """

        template = ChatPromptTemplate([
            ("human", final_summary_prompt_text)
        ])

        summary_prompt_template = template.invoke(
            {
                "summary_prompt_content": summary_prompt_content,
                "review_raw_text": review_raw_text
            }
        )

        return StrOutputParser().parse(summary_prompt_template.to_messages()[0].content)


    @staticmethod
    def parse_review_output(text: str) -> tuple[List[Dict], List[Dict]]:
        comments = []
        security_issues = []

        lines = text.strip().split('\n')

        for line in lines:
            line = line.strip()
            security_match = re.match(r"SECURITY:([^:]+):(\d+):(.+)", line)
            comment_match = re.match(r"([^:]+):(\d+):(.+)", line)

            if security_match:
                try:
                    file, line_num, issue = security_match.groups()
                    security_issues.append({
                        "file": file.strip(),
                        "line": int(line_num.strip()),
                        "issue": issue.strip()
                    })
                except ValueError:
                    logger.warning(f"Could not parse security issue line: {line}")
            elif comment_match:
                try:
                    file, line_num, comment = comment_match.groups()
                    comments.append({
                        "file": file.strip(),
                        "line": int(line_num.strip()),
                        "comment": comment.strip()
                    })
                except ValueError:
                    logger.warning(f"Could not parse comment line: {line}")
            else:
                logger.warning(f"Line did not match expected comment or security issue format: {line}")
        return comments, security_issues


    async def send_review_request(self, pr_details: dict) -> ParsedReviewOutput | None:
        """
        Sends a review request to the MCP server, processes the LLM responses, and returns
        structured review output.

        Args:
            pr_details (dict): A dictionary containing PR details including 'pr_id', 'diff_url',
                               'repo_name', 'repo_owner', and 'installation_id'.

        Returns:
            ParsedReviewOutput | None: An object containing the summary, comments, and security issues,
                                       or None if the review process fails.
        """
        pr_id = pr_details.get('pr_id', 0)
        repo = f"{pr_details.get('repo_owner', 'N/A')}/{pr_details.get('repo_name', 'N/A')}"
        try:
            installation_id = pr_details['installation_id']
            access_token = self.github_utils.get_installation_token(installation_id)

            if not access_token:
                logger.error(f"No access token available for fetching diff for PR #{pr_id}.")
                return None

            diff_content = self.github_utils.get_pr_diff(pr_details['diff_url'], access_token)

            if not diff_content:
                logger.warning(f"Diff content for PR #{pr_id} is empty. Skipping review.")
                return None

            guidelines = self.load_guidelines()
            if not guidelines:
                logger.warning(f"Guidelines content for PR #{pr_id} is empty. Review might be less effective.")

            logger.info(f"Building review prompt for PR #{pr_id}.")
            review_prompt_string = self.build_review_prompt(
                repo=repo,
                pr_id=pr_id,
                guidelines=guidelines,
                diff=diff_content
            )
            logger.debug(f"Review prompt built. Length: {len(review_prompt_string)} chars.")

            review_input_for_mcp = HFPassthroughInputClient(
                model_name=os.getenv("HUGGING_FACE_REVIEW_MODEL", "meta-llama/Meta-Llama-3-8B-Instruct"),
                inputs=review_prompt_string
            )

            logger.info(f"Calling MCP server for review generation for PR #{pr_id}.")
            review_raw_hf_response = None
            async with self.mcp_client as client:
                review_raw_hf_response = await client.call_tool(
                    name="llm_invoke_model",
                    arguments={"input_data": review_input_for_mcp.model_dump()},
                    timeout=self.mcp_client_timeout
                )

            logger.info(f"Received MCP response for review generation: {review_raw_hf_response}")

            review_raw_text = None
            if review_raw_hf_response and review_raw_hf_response.data:
                try:
                    parsed_content = review_raw_hf_response.data
                    if parsed_content.response_data and \
                       isinstance(parsed_content["response_data"], dict) and \
                       "generated_text" in parsed_content["response_data"]:
                        review_raw_text = parsed_content["response_data"]["generated_text"]
                        logger.info(
                            f"Received raw review text from MCP server for PR #{pr_id}. Length: {len(review_raw_text)} chars.")
                        logger.debug(f"Raw review text (first 200 chars): {review_raw_text[:200]}...")
                    else:
                        logger.error(
                            f"Parsed content missing 'response_data' or 'generated_text' for PR #{pr_id}: {parsed_content}")
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to decode JSON from review response content for PR #{pr_id}: {e}. Raw text: {review_raw_hf_response.content[0].text}", exc_info=True)
                except Exception as e:
                    logger.error(f"Unexpected error processing review response content for PR #{pr_id}: {e}", exc_info=True)

            if not review_raw_text:
                logger.error(
                    f"Failed to get valid raw review text from LLM response via MCP for PR #{pr_id}. Response: {review_raw_hf_response}")
                return None


            logger.info(f"Building summary prompt for PR #{pr_id}.")
            summary_prompt_string = self.build_summary_prompt(review_raw_text=review_raw_text)
            logger.debug(f"Summary prompt built. Length: {len(summary_prompt_string)} chars.")

            summary_input_for_mcp = HFPassthroughInputClient(
                model_name=os.getenv("MODEL_NAME", "meta-llama/Meta-Llama-3-8B-Instruct"),
                inputs=summary_prompt_string
            )

            logger.info(f"Calling MCP server for summary generation for PR #{pr_id}.")
            summary_raw_hf_response = None
            async with self.mcp_client as client:
                summary_raw_hf_response = await client.call_tool(
                    name="llm_invoke_model",
                    arguments={"input_data": summary_input_for_mcp.model_dump()},
                    timeout=self.mcp_client_timeout
                )

            summary_final_text = "No summary generated."
            # Check if content exists and is a list, then try to parse the text within it
            if summary_raw_hf_response and summary_raw_hf_response.content and \
               isinstance(summary_raw_hf_response.content, list) and \
               len(summary_raw_hf_response.content) > 0 and \
               hasattr(summary_raw_hf_response.content[0], 'text'):
                try:
                    # The 'text' attribute contains a JSON string, which needs to be parsed
                    parsed_content = json.loads(summary_raw_hf_response.content[0].text)
                    if parsed_content.get("response_data") and \
                       isinstance(parsed_content["response_data"], dict) and \
                       "generated_text" in parsed_content["response_data"]:
                        summary_final_text = parsed_content["response_data"]["generated_text"].strip()
                        logger.info(f"Received summary text from MCP server for PR #{pr_id}.")
                        logger.debug(f"Summary text (first 100 chars): {summary_final_text[:100]}...")
                    else:
                        logger.warning(
                            f"Parsed content missing 'response_data' or 'generated_text' for summary PR #{pr_id}: {parsed_content}")
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to decode JSON from summary response content for PR #{pr_id}: {e}. Raw text: {summary_raw_hf_response.content[0].text}", exc_info=True)
                except Exception as e:
                    logger.warning(f"Unexpected error processing summary response content for PR #{pr_id}: {e}", exc_info=True)


            logger.info(f"Parsing review output for PR #{pr_id}.")
            comments, security_issues = self.parse_review_output(review_raw_text)
            logger.info(f"Parsed {len(comments)} comments and {len(security_issues)} security issues for PR #{pr_id}.")

            return ParsedReviewOutput(
                summary=summary_final_text,
                comments=[Comment(**c) for c in comments],
                security_issues=[SecurityIssue(**s) for s in security_issues]
            )

        except Exception as e:
            logger.error(f"Failed to get review payload for PR #{pr_id} from MCP server: {str(e)}", exc_info=True)
        return ParsedReviewOutput(
                summary="PR review summary - none",
                comments=[],
                security_issues=[]
            )


    def check_mcp_server_health(self) -> str:
        if not self.mcp_url:
            return "not_configured"
        try:
            health_url = self.mcp_url.replace("/mcp/", "/health")
            logger.debug(f"Checking MCP server health at: {health_url}")
            mcp_response = requests.get(health_url, timeout=int(os.getenv("MCP_HEALTH_CHECK_TIMEOUT", 3)))
            if mcp_response.status_code == 200:
                logger.info("MCP server health check successful.")
                return "reachable"
            else:
                logger.warning(
                    f"MCP server health check failed with status: {mcp_response.status_code}. Response: {mcp_response.text}")
                return f"unreachable (status: {mcp_response.status_code})"
        except requests.exceptions.RequestException as e:
            logger.error(f"MCP server health check failed due to request error: {e}", exc_info=True)
            return f"unreachable (error: {e})"
        except Exception as e:
            logger.error(f"Unexpected error during MCP server health check: {e}", exc_info=True)
            return f"unreachable (unexpected error: {e})"