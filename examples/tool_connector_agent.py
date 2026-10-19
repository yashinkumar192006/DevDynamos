"""Integration pattern 2 — an agent that uses a tool / data connector.

Shows how to **wrap a tool** so every protected read goes through the
gateway. The synthetic CRM below keeps its raw data store private; the
agent-facing tool translates each call into a ContextShield secure request,
so field-level policy (e.g. mandatory masking of customer contact data)
applies no matter what the host agent asks for.

Designed for the seeded support identity ``eve.johnson`` (see
``backend/app/seed.py`` for demo passwords):

    python examples/tool_connector_agent.py

Honesty note: the wrapper is the enforcement point. If the host agent can
still call ``_raw_store`` directly, nothing is protected — remove or
restrict that path in real deployments.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

import _bootstrap
from contextshield import ConfigurationError

# Synthetic data only. These records exist purely to illustrate the shape of
# a tool call; the gateway never reads this store.
_RAW_STORE = {
    "CUS001": {
        "contact_email": "n***@acme-robotics.example",
        "contact_phone": "+1-***-0101",
    },
    "CUS003": {
        "contact_email": "m***@initech-soft.example",
        "contact_phone": "+1-***-0203",
    },
}


@dataclass(frozen=True)
class ToolResult:
    """What a tool call returns to the host agent."""

    status: str          # "ok" | "denied"
    data: dict[str, Any]
    explanation: str


class GuardedCrmTool:
    """The only tool surface the agent is allowed to use.

    Every call carries an explicit, user-attributable ``purpose`` — tool
    arguments are *requests*, and the gateway decides what (if anything) is
    disclosed, applying field-level transforms such as masking.
    """

    name = "crm_lookup"

    def __init__(self, client: Any) -> None:
        self._client = client

    def lookup_customer_contact(
        self, customer_id: str, *, purpose: str, session_id: str | None = None
    ) -> ToolResult:
        if not purpose or not purpose.strip():
            # A tool call without a stated purpose is rejected *before* any
            # data access — purpose cannot default to "whatever".
            raise ConfigurationError(
                "crm_lookup requires an explicit purpose for every call"
            )

        result = self._client.secure_request(
            resource="customer_records",
            data_fields=["contact_email", "contact_phone"],
            purpose=purpose,
            target_entity=customer_id,
            session_id=session_id,
        )

        if result.blocked:
            return ToolResult(
                status="denied",
                data={},
                explanation=(
                    "Policy denied this lookup "
                    f"({', '.join(sorted({d.reason_code for d in result.fields.values() if d.reason_code})) or 'no reason code'})."
                ),
            )

        # Approved — hand the host agent only the transformed values the
        # gateway released (masking already applied server-side).
        notes = []
        transforms = sorted(
            {d.action for d in result.fields.values() if d.action != "ALLOW"}
        )
        if transforms:
            notes.append(f"field protections applied: {', '.join(transforms)}")
        return ToolResult(
            status="ok",
            data=result.granted_values(),
            explanation="; ".join(notes) or "full access to the requested fields",
        )


def main() -> None:
    client = _bootstrap.build_client()
    tool = GuardedCrmTool(client)

    print("Support agent uses the guarded CRM tool (customer contact data)")
    result = tool.lookup_customer_contact(
        "CUS003", purpose="customer_service", session_id="demo-tool-agent"
    )
    print(f"  status:  {result.status}")
    print(f"  data:    {result.data}")
    print(f"  note:    {result.explanation}")

    print("\nTool call without a purpose is rejected locally (fail closed)")
    try:
        tool.lookup_customer_contact("CUS003", purpose="")
    except ConfigurationError as exc:
        print(f"  rejected: {exc}")

    print("\nOut-of-scope resource for this identity is denied by policy")
    denied = client.secure_request(
        resource="employee_salary",
        data_fields=["base_salary"],
        purpose="hr_review",
        target_entity="EMP002",
        session_id="demo-tool-agent",
    )
    print(f"  decision: {denied.overall_decision} "
          f"({', '.join(sorted({d.reason_code for d in denied.fields.values() if d.reason_code}))})")


if __name__ == "__main__":
    sys.exit(_bootstrap.run_safely(main))
