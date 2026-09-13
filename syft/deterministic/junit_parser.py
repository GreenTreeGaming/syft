"""Parse pytest JUnit XML into failed pytest node IDs."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath


class JUnitParseError(ValueError):
    """Raised when a JUnit document is malformed or unreadable."""


def parse_failed_tests(xml_path: Path) -> list[str]:
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError) as error:
        raise JUnitParseError(f"Could not parse JUnit XML at {xml_path}: {error}") from error

    failed: list[str] = []
    for case in root.iter("testcase"):
        if not any(child.tag.rsplit("}", 1)[-1] in {"failure", "error"} for child in case):
            continue
        node_id = _node_id_for_case(case)
        if node_id and node_id not in failed:
            failed.append(node_id)
    return failed


def _node_id_for_case(case: ET.Element) -> str | None:
    name = (case.get("name") or "").strip()
    if not name:
        return None
    if "::" in name:
        return name

    file_attr = (case.get("file") or "").strip()
    classname = (case.get("classname") or "").strip()
    class_name: str | None = None

    if file_attr:
        file_path = PurePosixPath(file_attr).as_posix()
        dotted_file = file_path.removesuffix(".py").replace("/", ".")
        if classname.startswith(f"{dotted_file}."):
            class_name = classname[len(dotted_file) + 1 :].split(".")[-1]
    elif classname:
        pieces = classname.split(".")
        if pieces[-1].startswith("Test"):
            class_name = pieces.pop()
        file_path = "/".join(pieces) + ".py"
    else:
        return name

    parts = [file_path]
    if class_name:
        parts.append(class_name)
    parts.append(name)
    return "::".join(parts)

