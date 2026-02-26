"""
Gemini FunctionDeclaration schemas for all agent tools.
Import TOOLS into agent.py to register them with the model.
"""

import google.generativeai as genai

_get_top_risk_assets = genai.protos.FunctionDeclaration(
    name="get_top_risk_assets",
    description=(
        "Returns the top N highest-risk assets from the security database, "
        "ranked by maximum CVSS vulnerability score. Use this when the user "
        "asks about risky assets, vulnerable systems, or CVSS scores."
    ),
    parameters=genai.protos.Schema(
        type=genai.protos.Type.OBJECT,
        properties={
            "limit": genai.protos.Schema(
                type=genai.protos.Type.INTEGER,
                description="Number of assets to return. Default is 10.",
            )
        },
    ),
)

_get_incident_trends = genai.protos.FunctionDeclaration(
    name="get_incident_trends",
    description=(
        "Returns monthly incident counts and resolution rates for the past N months. "
        "Use this when the user asks about incident history, trends over time, "
        "or resolution performance."
    ),
    parameters=genai.protos.Schema(
        type=genai.protos.Type.OBJECT,
        properties={
            "months": genai.protos.Schema(
                type=genai.protos.Type.INTEGER,
                description="Number of past months to include. Default is 6.",
            )
        },
    ),
)

_get_compliance_summary = genai.protos.FunctionDeclaration(
    name="get_compliance_summary",
    description=(
        "Returns compliance percentages grouped by framework and category. "
        "Available frameworks: 'NIST CSF', 'SOC 2', 'ISO 27001', 'Zero Trust'. "
        "Use this when the user asks about compliance, controls, or audit status."
    ),
    parameters=genai.protos.Schema(
        type=genai.protos.Type.OBJECT,
        properties={
            "framework": genai.protos.Schema(
                type=genai.protos.Type.STRING,
                description=(
                    "Optional framework filter. One of: 'NIST CSF', 'SOC 2', "
                    "'ISO 27001', 'Zero Trust'. Omit to get all frameworks."
                ),
            )
        },
    ),
)

_get_kill_chain_analysis = genai.protos.FunctionDeclaration(
    name="get_kill_chain_analysis",
    description=(
        "Returns incident counts and attacker footprint broken down by "
        "Cyber Kill Chain phase (Reconnaissance, Weaponization, Delivery, etc.). "
        "Use this when the user asks about attack phases, kill chain, or threat actor activity."
    ),
    parameters=genai.protos.Schema(
        type=genai.protos.Type.OBJECT,
        properties={},
    ),
)

_get_asset_details = genai.protos.FunctionDeclaration(
    name="get_asset_details",
    description=(
        "Returns operational asset inventory details: hostname, IP address, owner team, "
        "physical location, operating system, and last patch date. Optionally filtered by "
        "asset type or criticality tier. This is DIFFERENT from get_top_risk_assets — use "
        "get_top_risk_assets for CVSS/vulnerability rankings, and use get_asset_details to "
        "understand WHO owns the exposed assets, WHERE they are, and WHEN they were last patched. "
        "Always call this when the question involves exposed or high-criticality assets and "
        "a complete picture (ownership, patch status, location) is needed for prioritization."
    ),
    parameters=genai.protos.Schema(
        type=genai.protos.Type.OBJECT,
        properties={
            "asset_type": genai.protos.Schema(
                type=genai.protos.Type.STRING,
                description="Optional asset type filter.",
            ),
            "criticality": genai.protos.Schema(
                type=genai.protos.Type.STRING,
                description="Optional criticality filter: 'Critical', 'High', 'Medium', or 'Low'.",
            ),
        },
    ),
)

# Single Tool object containing all declarations — pass this to GenerativeModel
TOOLS = genai.protos.Tool(
    function_declarations=[
        _get_top_risk_assets,
        _get_incident_trends,
        _get_compliance_summary,
        _get_kill_chain_analysis,
        _get_asset_details,
    ]
)
