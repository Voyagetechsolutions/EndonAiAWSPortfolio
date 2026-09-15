"""Assemble Lambda deployment packages from the monorepo's source folders."""

from __future__ import annotations

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build" / "lambda"


def stage_lambda_source(name: str, *source_roots: Path) -> str:
    """Copy every Python package under ``source_roots`` into one asset directory.

    Endon functions depend only on boto3, which the Lambda runtime provides, plus
    Endon's own packages. A plain copy is enough, so synthesis needs no Docker.
    """
    target = BUILD_DIR / name
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for root in source_roots:
        for package in sorted(p for p in root.iterdir() if (p / "__init__.py").is_file()):
            shutil.copytree(
                package,
                target / package.name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
    return str(target)
