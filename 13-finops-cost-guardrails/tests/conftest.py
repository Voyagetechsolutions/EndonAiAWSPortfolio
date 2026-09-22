from pathlib import Path

import pytest

from endon_finops.costs import CostRow, load_file

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def anomalous() -> list[CostRow]:
    return load_file(FIXTURES / "anomalous.json")


@pytest.fixture
def clean() -> list[CostRow]:
    return load_file(FIXTURES / "clean.json")
