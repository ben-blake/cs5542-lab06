"""
AI agent implementation for Lab 6.
Uses Gemini 3.0 Flash Preview with native function-calling to answer
natural-language questions about the cybersecurity database.
"""

import os
from dotenv import load_dotenv
import google.generativeai as genai
import streamlit as st

from agent.tool_schemas import TOOLS
from agent import tools as tool_fns

load_dotenv()


def _get_secret(key):
    """Read from env vars (local) or st.secrets (Streamlit Cloud)."""
    val = os.getenv(key)
    if val:
        return val
    try:
        return st.secrets[key]
    except (KeyError, FileNotFoundError):
        return None

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant with access to tools \
that query a live Snowflake security database containing assets, vulnerabilities, \
incidents, compliance controls, and threat actor data.

When answering questions:
- Always call the relevant tool(s) to retrieve live data before answering.
- Ground every claim in the tool results — do not fabricate numbers.
- Be concise and actionable. Highlight the most important findings first.
- For complex multi-part questions, identify EVERY tool that provides distinct, \
relevant information and call each one before synthesizing your answer. Do not stop \
after one or two tools if additional tools would add new dimensions (e.g. ownership, \
patch status, attack phases, compliance gaps).
- get_top_risk_assets and get_asset_details serve different purposes: the first ranks \
by vulnerability severity, the second provides operational details (owner, location, \
patch date). Use both when prioritization recommendations are needed.
"""

MAX_ITERATIONS = 5

# Map tool names to the actual Python functions
TOOL_DISPATCH = {
    "get_top_risk_assets": tool_fns.get_top_risk_assets,
    "get_incident_trends": tool_fns.get_incident_trends,
    "get_compliance_summary": tool_fns.get_compliance_summary,
    "get_kill_chain_analysis": tool_fns.get_kill_chain_analysis,
    "get_asset_details": tool_fns.get_asset_details,
}


def run_agent(user_query: str, conn) -> tuple[str, list[dict]]:
    """
    Run the agent loop for a single user query.

    Args:
        user_query: The natural-language question from the user.
        conn: Active Snowflake connection (shared with dashboard).

    Returns:
        Tuple of (final_answer: str, tool_log: list[dict]).
        tool_log entries have keys: 'tool', 'args', 'result_preview'.
    """
    api_key = _get_secret("GEMINI_API_KEY")
    if not api_key:
        return "Error: GEMINI_API_KEY not set in environment.", []

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name="gemini-2.5-flash",
        tools=[TOOLS],
        system_instruction=SYSTEM_PROMPT,
    )

    try:
        chat = model.start_chat()
        response = chat.send_message(user_query)
        tool_log = []

        for _ in range(MAX_ITERATIONS):
            # Collect all function_call parts from this response
            function_calls = [
                part.function_call
                for candidate in response.candidates
                for part in candidate.content.parts
                if part.function_call.name  # non-empty name means it's a real call
            ]

            if not function_calls:
                # No tool calls — Gemini is done, return the text answer
                return _extract_text(response), tool_log

            # Execute each function call and collect responses
            tool_responses = []
            for fc in function_calls:
                fn = TOOL_DISPATCH.get(fc.name)
                if fn is None:
                    result = f'{{"error": "Unknown tool: {fc.name}"}}'
                else:
                    kwargs = dict(fc.args)
                    result = fn(conn, **kwargs)

                tool_log.append({
                    "tool": fc.name,
                    "args": dict(fc.args),
                    "result_preview": result[:200],
                })

                tool_responses.append(
                    genai.protos.Part(
                        function_response=genai.protos.FunctionResponse(
                            name=fc.name,
                            response={"result": result},
                        )
                    )
                )

            response = chat.send_message(tool_responses)

        # Exhausted iterations — return whatever text we have
        text = _extract_text(response)
        return text + "\n\n*(Note: agent reached max reasoning steps)*", tool_log

    except Exception as e:
        error_name = type(e).__name__
        if "ResourceExhausted" in error_name or "429" in str(e):
            return "Gemini API rate limit reached. Please wait a minute and try again.", []
        return f"Agent error: {error_name} — {e}", []


def _extract_text(response) -> str:
    """Pull plain text from a Gemini response, handling empty parts."""
    parts = [
        part.text
        for candidate in response.candidates
        for part in candidate.content.parts
        if hasattr(part, "text") and part.text
    ]
    return "\n".join(parts) if parts else "(No text response from agent)"
