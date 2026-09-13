from pathlib import Path

from syft import __main__ as cli


def test_demo_main_supplies_complete_fixture_defaults(mocker, tmp_path: Path) -> None:
    demo_directory = tmp_path / "demo"
    fixture_repository = tmp_path / "syft-testing"
    mocker.patch.object(cli.tempfile, "mkdtemp", return_value=str(demo_directory))
    watch_main = mocker.patch.object(cli, "_watch_main", return_value=0)

    assert cli._demo_main(["--repo", str(fixture_repository)]) == 0

    arguments = watch_main.call_args.args[0]
    assert arguments == [
        "--repo",
        str(fixture_repository),
        "--github-repository",
        "GreenTreeGaming/syft-testing",
        "--branch",
        "codex/regression-fixture",
        "--green-branch",
        "main",
        "--artifact-name",
        "pytest-junit",
        "--attempts",
        "5",
        "--timeout",
        "60",
        "--use-openai",
        "--execute",
        "--once",
        "--watch-state-file",
        str(demo_directory / "watch-state.json"),
        "--action-state-file",
        str(demo_directory / "action-state.json"),
        "--history-db",
        str(demo_directory / "history.sqlite3"),
        "--output-dir",
        str(demo_directory / "runs"),
        "--trace-dir",
        str(demo_directory / "traces"),
    ]


def test_demo_main_can_rehearse_without_external_writes(mocker, tmp_path: Path) -> None:
    mocker.patch.object(cli.tempfile, "mkdtemp", return_value=str(tmp_path / "demo"))
    watch_main = mocker.patch.object(cli, "_watch_main", return_value=0)

    assert cli._demo_main(["--repo", str(tmp_path / "fixture"), "--dry-run"]) == 0

    arguments = watch_main.call_args.args[0]
    assert "--dry-run" in arguments
    assert "--execute" not in arguments


def test_demo_environment_loads_known_keys_without_overriding_shell(mocker, tmp_path: Path) -> None:
    environment = tmp_path / ".env"
    environment.write_text(
        "GITHUB_TOKEN=file-token\n"
        "OPENAI_API_KEY='openai-key'\n"
        'LINEAR_TEAM_ID="linear-team"\n'
        "UNRELATED_SECRET=ignored\n",
        encoding="utf-8",
    )
    mocker.patch.dict(
        cli.os.environ,
        {"GITHUB_TOKEN": "shell-token"},
        clear=True,
    )

    cli._load_demo_environment(environment)

    assert cli.os.environ["GITHUB_TOKEN"] == "shell-token"
    assert cli.os.environ["OPENAI_API_KEY"] == "openai-key"
    assert cli.os.environ["LINEAR_TEAM_ID"] == "linear-team"
    assert "UNRELATED_SECRET" not in cli.os.environ
