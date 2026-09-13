from pathlib import Path

import pytest

from syft.deterministic.git_analysis import GitAnalysisError, find_directly_imported_files


def test_maps_direct_imports_to_repository_files(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "checkout.py").write_text("", encoding="utf-8")
    (tmp_path / "app" / "payments.py").write_text("", encoding="utf-8")
    (tmp_path / "tests" / "test_checkout.py").write_text(
        "from app.checkout import calculate_total\nimport app.payments\nimport json\n",
        encoding="utf-8",
    )
    assert find_directly_imported_files(tmp_path, "tests/test_checkout.py::test_checkout") == [
        "app/checkout.py",
        "app/payments.py",
    ]


def test_maps_relative_import(tmp_path: Path) -> None:
    package = tmp_path / "tests" / "helpers"
    package.mkdir(parents=True)
    (package / "factory.py").write_text("", encoding="utf-8")
    (package / "test_item.py").write_text("from .factory import make_item\n", encoding="utf-8")
    assert find_directly_imported_files(tmp_path, "tests/helpers/test_item.py::test_item") == [
        "tests/helpers/factory.py"
    ]


def test_missing_test_file_raises(tmp_path: Path) -> None:
    with pytest.raises(GitAnalysisError):
        find_directly_imported_files(tmp_path, "tests/missing.py::test_missing")

