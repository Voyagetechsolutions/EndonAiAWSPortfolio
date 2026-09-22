from pathlib import Path

import pytest

from endon_tfscan.plan import Plan

PLANS = Path(__file__).resolve().parents[1] / "terraform" / "plans"


@pytest.fixture
def insecure_plan() -> Plan:
    return Plan.from_file(PLANS / "insecure.plan.json")


@pytest.fixture
def secure_plan() -> Plan:
    return Plan.from_file(PLANS / "secure.plan.json")
