import ast

import pytest

from syft.integrations import IntegrationError
from syft.integrations.github import quarantine_pytest_source


def test_quarantine_adds_import_and_decorator() -> None:
    source = '''"""Tests."""
from __future__ import annotations

from decimal import Decimal


def test_checkout() -> None:
    assert Decimal("1") == Decimal("2")
'''
    updated = quarantine_pytest_source(source, "test_checkout", "Syft evidence")
    ast.parse(updated)
    assert 'import pytest' in updated
    assert '@pytest.mark.skip(reason="Syft evidence")\ndef test_checkout' in updated
    assert updated.index("from __future__") < updated.index("import pytest")


def test_quarantine_is_idempotent_and_handles_parameterized_node_name() -> None:
    source = "import pytest\n\ndef test_value():\n    assert False\n"
    once = quarantine_pytest_source(source, "test_value[param]", "reason")
    twice = quarantine_pytest_source(once, "test_value[param]", "reason")
    assert once == twice
    assert once.count("@pytest.mark.skip") == 1


def test_quarantine_rejects_missing_function() -> None:
    with pytest.raises(IntegrationError):
        quarantine_pytest_source("def test_other(): pass\n", "test_missing", "reason")

