from pathlib import Path

import pytest

from syft.deterministic.junit_parser import JUnitParseError, parse_failed_tests


def test_parses_multiple_pytest_failures(tmp_path: Path) -> None:
    xml = tmp_path / "junit.xml"
    xml.write_text(
        """<?xml version="1.0"?>
<testsuites><testsuite>
  <testcase classname="tests.test_checkout" name="test_checkout" file="tests/test_checkout.py"><failure>nope</failure></testcase>
  <testcase classname="tests.test_users.TestUsers" name="test_create_user"><error>boom</error></testcase>
  <testcase classname="tests.test_ok" name="test_ok" file="tests/test_ok.py" />
</testsuite></testsuites>""",
        encoding="utf-8",
    )
    assert parse_failed_tests(xml) == [
        "tests/test_checkout.py::test_checkout",
        "tests/test_users.py::TestUsers::test_create_user",
    ]


def test_preserves_explicit_node_id(tmp_path: Path) -> None:
    xml = tmp_path / "junit.xml"
    xml.write_text(
        '<testsuite><testcase name="tests/test_x.py::test_x[a]"><failure /></testcase></testsuite>',
        encoding="utf-8",
    )
    assert parse_failed_tests(xml) == ["tests/test_x.py::test_x[a]"]


def test_malformed_xml_raises(tmp_path: Path) -> None:
    xml = tmp_path / "junit.xml"
    xml.write_text("<testsuite>", encoding="utf-8")
    with pytest.raises(JUnitParseError):
        parse_failed_tests(xml)

