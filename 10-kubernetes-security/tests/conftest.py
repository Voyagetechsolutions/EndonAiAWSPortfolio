from pathlib import Path

import pytest

from endon_k8s.manifests import K8sObject, load_file

MANIFESTS = Path(__file__).resolve().parents[1] / "manifests"


def _load(name: str) -> list[K8sObject]:
    return load_file(MANIFESTS / name)


@pytest.fixture
def insecure_pods() -> list[K8sObject]:
    return _load("insecure.yaml")


@pytest.fixture
def secure_pods() -> list[K8sObject]:
    return _load("secure.yaml")


@pytest.fixture
def insecure_rbac() -> list[K8sObject]:
    return _load("rbac-insecure.yaml")


@pytest.fixture
def secure_rbac() -> list[K8sObject]:
    return _load("rbac-secure.yaml")
