"""
Billing plan definitions.

Three tiers with separate monthly quotas for scans and vulnerability resolutions:
  - free:       2 scans,    2 resolves
  - team:       500 scans,  500 resolves
  - enterprise: 2000 scans, 2000 resolves
"""

from typing import TypedDict

VALID_PLANS = ("starter", "team", "enterprise")


class PlanConfig(TypedDict):
    scan_quota: int
    resolve_quota: int


PLANS: dict[str, PlanConfig] = {
    "starter": {
        "scan_quota": 2,
        "resolve_quota": 2,
    },
    "team": {
        "scan_quota": 500,
        "resolve_quota": 500,
    },
    "enterprise": {
        "scan_quota": 2000,
        "resolve_quota": 2000,
    },
}


def get_plan(plan_name: str) -> PlanConfig:
    """Return the PlanConfig for *plan_name*, falling back to 'starter' for unknown names."""
    return PLANS.get(plan_name, PLANS["starter"])
