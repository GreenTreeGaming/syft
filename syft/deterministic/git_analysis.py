"""Collect changed-file and direct-import evidence using Git and AST."""

from __future__ import annotations

import ast
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from syft.deterministic.rerunner import rerun_test


class GitAnalysisError(RuntimeError):
    """Raised when Git or source analysis cannot produce valid evidence."""


class RelatedCodeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    changed_files: list[str] = Field(default_factory=list)
    related_files: list[str] = Field(default_factory=list)
    matching_related_files: list[str] = Field(default_factory=list)
    related_code_changed: bool


def get_changed_files(repo_path: Path, base_commit: str, current_commit: str) -> list[str]:
    completed = _run_git(
        repo_path,
        ["diff", "--name-only", "--diff-filter=ACMRT", base_commit, current_commit, "--"],
    )
    return sorted({PurePosixPath(line).as_posix() for line in completed.stdout.splitlines() if line.strip()})


def find_directly_imported_files(repo_path: Path, test_node_id: str) -> list[str]:
    relative_test = PurePosixPath(test_node_id.split("::", 1)[0])
    test_path = repo_path.joinpath(*relative_test.parts)
    if not test_path.is_file():
        raise GitAnalysisError(f"Test file does not exist: {relative_test}")
    try:
        tree = ast.parse(test_path.read_text(encoding="utf-8"), filename=str(relative_test))
    except (OSError, SyntaxError) as error:
        raise GitAnalysisError(f"Could not parse imports from {relative_test}: {error}") from error

    modules: set[tuple[str, int]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update((alias.name, 0) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add((node.module or "", node.level))

    related: set[str] = set()
    for module, level in modules:
        for candidate in _module_candidates(relative_test, module, level):
            absolute = repo_path.joinpath(*candidate.parts)
            if absolute.is_file():
                related.add(candidate.as_posix())
    return sorted(related)


def analyze_related_code(
    repo_path: Path,
    last_green_commit: str,
    current_commit: str,
    test_node_id: str,
) -> RelatedCodeResult:
    changed = get_changed_files(repo_path, last_green_commit, current_commit)
    related = find_directly_imported_files(repo_path, test_node_id)
    matching = sorted(set(changed).intersection(related))
    return RelatedCodeResult(
        changed_files=changed,
        related_files=related,
        matching_related_files=matching,
        related_code_changed=bool(matching),
    )


def failed_at_commit(
    repo_path: Path,
    commit: str,
    test_node_id: str,
    timeout_seconds: int = 60,
) -> bool | None:
    """Run the test once in a temporary detached worktree without touching the checkout."""

    with tempfile.TemporaryDirectory(prefix="syft-worktree-") as temporary:
        worktree = Path(temporary) / "repo"
        _run_git(repo_path, ["worktree", "add", "--detach", str(worktree), commit])
        try:
            test_file = worktree / test_node_id.split("::", 1)[0]
            if not test_file.is_file():
                return None
            attempt = rerun_test(worktree, test_node_id, attempts=1, timeout_seconds=timeout_seconds)[0]
            if attempt.exit_code in {0, 1}:
                return not attempt.passed
            return None
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=False,
            )


def _module_candidates(test_file: PurePosixPath, module: str, level: int) -> list[PurePosixPath]:
    if level:
        base = test_file.parent
        for _ in range(max(0, level - 1)):
            base = base.parent
        module_path = base.joinpath(*module.split(".")) if module else base
    else:
        module_path = PurePosixPath(*module.split("."))
    return [module_path.with_suffix(".py"), module_path / "__init__.py"]


def _run_git(repo_path: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise GitAnalysisError(f"Could not start Git: {error}") from error
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "unknown Git error"
        raise GitAnalysisError(f"Git {' '.join(arguments)} failed: {message}")
    return completed

