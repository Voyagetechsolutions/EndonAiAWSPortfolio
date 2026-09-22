from pathlib import Path

import pytest
from endon_siem.events import Event, load_file

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def attack_events() -> list[Event]:
    return load_file(FIXTURES / "attack.json")


@pytest.fixture
def benign_events() -> list[Event]:
    return load_file(FIXTURES / "benign.json")
