from pathlib import Path

import pytest

from endon_azure.resources import AzureResource, load_file

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def insecure() -> list[AzureResource]:
    return load_file(FIXTURES / "insecure.json")


@pytest.fixture
def secure() -> list[AzureResource]:
    return load_file(FIXTURES / "secure.json")
