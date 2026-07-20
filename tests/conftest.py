"""Shared test harness.

The contract schemas cross-reference each other by absolute ``$id`` URI, so we
load all five into a ``referencing.Registry`` and hand tests a ``validate`` /
``is_valid`` helper that resolves those ``$ref``s. Format checking is on
(``format-nongpl``) so ``uuid`` / ``date-time`` / ``uri`` formats are really
validated, not silently skipped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

CONTRACTS_DIR = Path(__file__).resolve().parents[1] / "contracts" / "v1"


@pytest.fixture(scope="session")
def registry() -> Registry:
    reg = Registry()
    for path in sorted(CONTRACTS_DIR.glob("*.schema.json")):
        schema = json.loads(path.read_text())
        reg = reg.with_resource(schema["$id"], Resource.from_contents(schema))
    return reg


def _validator(schema_ref: str | dict[str, Any], registry: Registry) -> Draft202012Validator:
    schema = {"$ref": schema_ref} if isinstance(schema_ref, str) else schema_ref
    return Draft202012Validator(
        schema,
        registry=registry,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


@pytest.fixture(scope="session")
def validate(registry: Registry) -> Callable[[str | dict[str, Any], Any], None]:
    def _validate(schema_ref: str | dict[str, Any], instance: Any) -> None:
        _validator(schema_ref, registry).validate(instance)

    return _validate


@pytest.fixture(scope="session")
def is_valid(registry: Registry) -> Callable[[str | dict[str, Any], Any], bool]:
    def _is_valid(schema_ref: str | dict[str, Any], instance: Any) -> bool:
        return _validator(schema_ref, registry).is_valid(instance)

    return _is_valid
