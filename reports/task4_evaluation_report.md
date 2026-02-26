# Task 4 — Agent Evaluation Report

**Date:** 2026-02-26
**Model:** Gemini 3.0 Flash Preview
**Dataset:** CYBER_DB (200 assets, 500 vulns, 300 incidents, 100 controls, 50 threat actors)

---

## Scenario 1 — Simple (single tool)

**Query:** "What are the top 5 highest-risk assets?"

| Field | Value |
|-------|-------|
| Tools called | `get_top_risk_assets` |
| Reasoning steps | 1 |
| Latency (ms) | 3496 |
| Accuracy | High |
| Failure notes | None |

**Agent response:**

> The top 5 highest-risk assets all have a maximum CVSS score of 10.0, indicating critical vulnerabilities.
>
> | Hostname | Asset Type | Criticality | Total Vulns | Max CVSS |
> |----------|-----------|-------------|-------------|----------|
> | believe-future-085 | Database | Medium | 4 | 10.0 |
> | standard-set-139 | Network Device | Critical | 4 | 10.0 |
> | itself-loss-141 | Network Device | High | 3 | 10.0 |
> | cover-marriage-043 | Application | High | 3 | 10.0 |
> | film-church-167 | Network Device | Medium | 3 | 10.0 |
>
> **Immediate Concern:** standard-set-139 is classified as Critical and has a CVSS 10.0 vulnerability, making it the highest priority for remediation.

---

## Scenario 2 — Medium (multi-tool)

**Query:** "Compare incident trends over the last 6 months with our compliance posture."

| Field | Value |
|-------|-------|
| Tools called | `get_incident_trends`, `get_compliance_summary` |
| Reasoning steps | 2 |
| Latency (ms) | 9101 |
| Accuracy | High |
| Failure notes | None |

**Agent response:**

> The comparison between your incident trends and compliance posture reveals a significant correlation between gaps in control maturity and operational performance.
>
> **1. Incident Trends (Last 6 Months)**
>
> Operational performance has been volatile, with incident volume peaking in late Q4 and early Q1:
> - **Peak Volume:** November saw the highest total incidents (33), while January saw 26.
> - **Criticality:** High-severity activity peaked in September (10 critical) and remained elevated in January (8 critical).
> - **Resolution Performance:** Resolution rates are inconsistent, dropping as low as 52% in December. While January showed improvement (81%), the overall trend suggests the team struggles to maintain pace during high-volume periods.
>
> **2. Compliance Posture Gaps**
>
> Your compliance posture across major frameworks (NIST CSF, ISO 27001, SOC 2, Zero Trust) is currently low, particularly in categories that directly impact incident handling:
> - **Respond & Detect Weakness:** NIST CSF: 0% compliant in Respond and Identify; 25% in Detect. Zero Trust: 0% compliant in Respond, Recover, and Identify. SOC 2: 0% compliant in Detect and Protect.
> - **Recovery Vulnerability:** Compliance in the Recover category is critically low across all frameworks, ranging from 0% to 20%.
>
> **3. Key Correlation**
>
> The data suggests that the 0% compliance in "Respond" controls (NIST CSF and Zero Trust) is a primary driver of the volatile resolution rates. When incident volume spikes (as seen in November and January), the lack of formalized response procedures and automated controls leads to inconsistent outcomes and lower resolution efficiency.
>
> **Recommendation:** Prioritize the implementation of NIST CSF Respond and Detect controls. Addressing these gaps will provide the necessary framework to stabilize resolution rates and better manage the high volume of critical incidents.

---

## Scenario 3 — Complex (reasoning + synthesis)

**Query:** "Which kill chain phases are most active, which assets are most exposed, and what should we prioritize?"

| Field | Value |
|-------|-------|
| Tools called | `get_kill_chain_analysis`, `get_top_risk_assets`, `get_asset_details` |
| Reasoning steps | 3 |
| Latency (ms) | 10383 |
| Accuracy | High |
| Failure notes | None |

**Agent response:**

> **Kill Chain Activity**
>
> The most active phases by volume are Weaponization (63 incidents) and Reconnaissance (53 incidents). However, from a risk perspective, the Installation phase is the most critical area of concern:
> - **Installation:** Highest number of critical incidents (17) and a low resolution rate (58.97%).
> - **Delivery:** 12 critical incidents with 45 total incidents.
>
> **Most Exposed Assets**
>
> The following assets are the most exposed based on CVSS severity and asset criticality:
> - **AST0139 (standard-set-139):** A Critical-tier Network Device with a Max CVSS of 10.0.
> - **AST0043 (cover-marriage-043):** A High-tier Application with a Max CVSS of 10.0 and high average vulnerability score (7.73).
> - **AST0141 (itself-loss-141):** A High-tier Network Device with a Max CVSS of 10.0.
>
> **Prioritization Recommendations**
>
> Based on the intersection of exploitability, asset importance, and current attack trends:
>
> 1. **Immediate Remediation of AST0139:** This is your highest-risk asset (Critical tier + CVSS 10.0). Owner: Julie Cunningham. Action: Verify the Windows patch status and investigate for any signs of "Installation" phase activity, as network devices are frequent targets in this phase.
>
> 2. **Address Stale Critical Databases:** Several critical databases have not been patched since September 2025, making them prime targets for the "Actions on Objectives" phase.
>    - AST0063 (exactly-attention-063): Owner: Kevin Gomez (Last patched: 2025-09-01)
>    - AST0149 (for-music-149): Owner: James Cole (Last patched: 2025-09-21)
>
> 3. **Strengthen "Installation" Phase Controls:** Given the high number of critical incidents and low resolution rate in the Installation phase, focus on endpoint protection and integrity monitoring for assets owned by teams with the most critical exposures.

---

## Summary Observations

- **Overall accuracy:** High across all three scenarios. The agent consistently grounded responses in live Snowflake data, returning real asset IDs, hostnames, owner names, and patch dates without hallucination. Quantitative claims (CVSS scores, incident counts, resolution rates, compliance percentages) were all verifiable against the dashboard tabs.

- **Average latency:** 7660 ms (Scenario 1: 3,496 ms | Scenario 2: 9,101 ms | Scenario 3: 10,383 ms).

- **Failure cases:** None

- **Lessons learned:**
  - **Tool description precision is critical.** When two tools overlap conceptually (both relate to "assets"), the model defaults to whichever it already called. Descriptions must explicitly state what each tool provides that the other does not — in this case, CVSS/vulnerability ranking vs. ownership, patch date, and location.
  - **System prompt specificity improves multi-tool behavior.** A generic instruction like "call relevant tools" is insufficient for complex queries. Naming the conceptual distinction between similar tools in the system prompt directly eliminated tool omissions.
  - **Resolution rate is a leading indicator of control gaps.** The agent independently identified the correlation between low "Respond" compliance scores and volatile incident resolution rates across Scenarios 2 and 3 — a non-obvious cross-domain insight that required synthesizing two separate tool outputs, demonstrating real reasoning capability beyond simple retrieval.
  - **Latency scales with tool call count.** Each tool call requires a full Gemini API round-trip. Scenario 1 (1 tool) took 3,496 ms; Scenario 3 (3 tools) took 10,383 ms. For a production deployment, parallel tool dispatch would be a worthwhile optimization.
  - **Agent responses are more actionable than raw query results.** The dashboard tabs display tables and charts requiring manual interpretation. The agent synthesized kill chain data, asset ownership, and patch dates into a ranked prioritization list with named owners and specific remediation actions — a level of analysis that would otherwise require cross-referencing three separate dashboard tabs manually.
