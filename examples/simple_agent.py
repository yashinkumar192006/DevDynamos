"""Integration pattern 1 — a simple existing Python AI agent.

Shows how an agent that *already exists* becomes privacy-aware with a small,
localized change: its protected lookup method stops querying the database
directly and instead submits a secure request to the gateway.

Designed for the seeded HR identity ``sarah.chen`` (see
``backend/app/seed.py`` for demo passwords):

    python examples/simple_agent.py

Honesty note: protection applies to the paths that actually go through the
gateway. In a real system you would make ``_fetch_salary`` the *only* way
the agent can read compensation data (remove/restrict direct database
access) — otherwise the old path would still leak.
"""

from __future__ import annotations

import sys
from typing import Any

import _bootstrap


class CompensationAgent:
    """A tiny stand-in for an existing agent.

    Before: ``_fetch_salary`` read employees straight from the database.
    After: it can only obtain data through the ContextShield gateway, which
    enforces identity, purpose, policy, field-level access — and records an
    audit event either way.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    def _fetch_salary(self, employee_id: str) -> Any:
        """The single protected data-access path of this agent."""
        return self._client.secure_request(
            resource="employee_salary",
            data_fields=["employee_id", "base_salary"],
            purpose="hr_review",          # purpose is required context, not proof
            target_entity=employee_id,
            session_id="demo-simple-agent",
        )

    def compensation_summary(self, employee_id: str) -> str:
        result = self._fetch_salary(employee_id)
        if result.blocked:
            reasons = sorted(
                {d.reason_code for d in result.fields.values() if d.reason_code}
            )
            return (
                f"Access to compensation data for {employee_id} was denied "
                f"by policy ({', '.join(reasons) or 'no reason given'})."
            )
        values = result.granted_values()
        return (
            f"{employee_id} compensation: base salary "
            f"{values.get('base_salary')} "
            f"[decision {result.overall_decision}, audit {result.audit_id}]"
        )

    def customer_note(self, customer_id: str) -> str:
        """A lookup this HR agent is *not* authorized for — handled, not crashed."""
        result = self._client.secure_request(
            resource="customer_records",
            data_fields=["contact_email"],
            purpose="customer_service",
            target_entity=customer_id,
            session_id="demo-simple-agent",
        )
        if result.blocked:
            return (
                f"Access to {customer_id} customer data was denied by policy — "
                "I can only work with employee records."
            )
        return f"{customer_id} contact: {result.granted_values()}"


def main() -> None:
    client = _bootstrap.build_client()
    agent = CompensationAgent(client)

    print("HR agent — authorized employee lookup")
    print(" ", agent.compensation_summary("EMP001"))

    print("\nHR agent — out-of-scope customer lookup")
    print(" ", agent.customer_note("CUS003"))


if __name__ == "__main__":
    sys.exit(_bootstrap.run_safely(main))
