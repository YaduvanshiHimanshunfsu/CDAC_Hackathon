"""AI-Powered Explainable Linux Security Assistant.

वज्र (Vajra) - Developed by Team_Red_Eagle.
Synthesizes causal provenance, counterfactual explanations, MITRE ATT&CK techniques,
and policy guidelines to answer analyst inquiries and guide containment workflows.
"""

from __future__ import annotations

from typing import Any


class SecurityAssistant:
    """Conversational and analytical assistant for Linux runtime security & reliability."""

    def __init__(self) -> None:
        self.conversation_history: list[dict[str, str]] = []

    def explain_incident(self, incident: dict[str, Any], graph_context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Generate structured explainability report for a security or reliability incident."""
        findings = incident.get("findings", [])
        counterfactual = incident.get("counterfactual", {})
        sec_score = incident.get("security_score", 0.0)
        rel_score = incident.get("reliability_score", 0.0)
        event = incident.get("event", {})
        event_type = event.get("event_type", "UNKNOWN")
        workload = event.get("workload", {}).get("workload_id", "default")
        target_obj = event.get("object_value", "unknown")

        # 1. Determine primary threat category
        if rel_score >= 0.70:
            category = "System Reliability & Pressure Failure"
            severity = "CRITICAL" if rel_score >= 0.85 else "HIGH"
        elif sec_score >= 0.85:
            category = "High-Severity Security Intrusion"
            severity = "CRITICAL"
        elif sec_score >= 0.60:
            category = "Suspicious Workload Behavioral Anomaly"
            severity = "HIGH"
        else:
            category = "Informational Telemetry Observation"
            severity = "LOW"

        # 2. Extract key evidence points
        evidence_list: list[str] = []
        mitre_list: set[str] = set()
        recommended_actions: list[str] = []

        for f in findings:
            evidence_list.extend(f.get("evidence", []))
            for m in f.get("mitre_techniques", []):
                mitre_list.add(m)
            rec = f.get("recommended_action")
            if rec and rec not in recommended_actions:
                recommended_actions.append(rec)

        # 3. Generate plain language explanation
        cf_text = counterfactual.get("verbalized_explanation", "No counterfactual conditions required.")
        summary = (
            f"The **वज्र (Vajra)** AI engine detected a **{severity}** {category.lower()} on workload `{workload}`. "
            f"Observed event: `{event_type}` targeting `{target_obj}`. "
            f"Overall Security Risk Score: **{sec_score:.2f}**, Reliability Risk Score: **{rel_score:.2f}**."
        )

        return {
            "category": category,
            "severity": severity,
            "summary": summary,
            "evidence": evidence_list,
            "mitre_techniques": sorted(list(mitre_list)),
            "counterfactual_reasoning": cf_text,
            "recommended_actions": recommended_actions,
            "containment_guidance": (
                "Recommended next step: Freeze workload cgroup or isolate network egress via 1-click policy action."
                if severity in ("CRITICAL", "HIGH")
                else "No immediate containment necessary. Continue monitoring."
            ),
        }

    def chat_query(
        self,
        query: str,
        recent_incidents: list[dict[str, Any]],
        graph_data: dict[str, Any] | None = None,
    ) -> str:
        """Answer operator questions in natural language with grounded context."""
        query_lower = query.lower()

        if not recent_incidents:
            return (
                "👋 **वज्र (Vajra) Security Assistant (Team_Red_Eagle)**: All monitored Linux workloads are currently operating within "
                "normal statistical baselines. No security threats or system pressure failures are active."
            )

        latest_inc = recent_incidents[-1]
        analysis = self.explain_incident(latest_inc)

        # Question routing
        if "why" in query_lower or "explain" in query_lower or "reason" in query_lower:
            evidence_bullets = "\n".join([f"- {e}" for e in analysis["evidence"][:4]])
            mitre_str = ", ".join(analysis["mitre_techniques"]) if analysis["mitre_techniques"] else "N/A"
            return (
                f"### 🛡️ वज्र AI Explainability Report: Incident `{latest_inc.get('event_id', 'latest')}`\n\n"
                f"{analysis['summary']}\n\n"
                f"**Key Empirical Evidence Detected:**\n{evidence_bullets}\n\n"
                f"**MITRE ATT&CK Mapping:** `{mitre_str}`\n\n"
                f"**Counterfactual Explanation:**\n> {analysis['counterfactual_reasoning']}\n\n"
                f"**Recommended Remediation:** {analysis['containment_guidance']}"
            )

        if "action" in query_lower or "remediate" in query_lower or "fix" in query_lower or "contain" in query_lower:
            actions = "\n".join([f"1. **{a}**" for a in analysis["recommended_actions"]])
            return (
                f"### 🚨 Recommended Corrective Actions for Workload `{latest_inc.get('event', {}).get('workload', {}).get('workload_id', 'target')}`\n\n"
                f"{actions}\n\n"
                f"🔒 *All containment actions are policy-governed with automatic 30-minute rollback TTL and cryptographic audit logging.*"
            )

        if "provenance" in query_lower or "lineage" in query_lower or "root cause" in query_lower:
            return (
                f"### 🔍 Causal Provenance & Root Cause Analysis\n\n"
                f"The target execution originated from parent process `{latest_inc.get('event', {}).get('attributes', {}).get('parent_executable', '/usr/lib/systemd/systemd')}` "
                f"which spawned `{latest_inc.get('event', {}).get('subject', {}).get('executable', 'target')}`.\n\n"
                f"You can explore the interactive Directed Acyclic Graph (DAG) in the **Provenance Lineage** panel above."
            )

        # General response
        return (
            f"**वज्र (Vajra) Assistant Summary**: The most critical active incident is on workload "
            f"`{latest_inc.get('event', {}).get('workload', {}).get('workload_id', 'unknown')}` with Security Score `{latest_inc.get('security_score', 0):.2f}`. "
            f"{analysis['counterfactual_reasoning']} Would you like me to execute containment or explain the causal provenance path?"
        )
