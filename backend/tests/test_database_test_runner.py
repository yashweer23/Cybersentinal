from unittest.mock import MagicMock
from uuid import UUID

from sqlalchemy.exc import OperationalError

from app.config import Settings
from scripts import run_database_tests as runner


def test_runner_cleans_only_its_created_database_even_when_pytest_fails(monkeypatch):
    settings = Settings(_env_file=None, app_env="development", postgres_db="keep_my_dev_data")
    monkeypatch.setattr(runner, "get_settings", lambda: settings)
    monkeypatch.setattr(runner, "uuid4", lambda: UUID(int=123))
    monkeypatch.setattr(runner.sys, "argv", ["run_database_tests"])
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    monkeypatch.setattr(runner, "create_engine", lambda *args, **kwargs: engine)
    child = MagicMock(return_value=MagicMock(returncode=2))
    monkeypatch.setattr(runner.subprocess, "run", child)

    assert runner.main() == 2
    name = f"cybersentinel_test_{UUID(int=123).hex}"
    statements = [str(call.args[0]) for call in connection.execute.call_args_list]
    assert statements == [f'CREATE DATABASE "{name}"', f'DROP DATABASE "{name}" WITH (FORCE)']
    assert child.call_args.kwargs["env"]["TEST_DATABASE_URL"].endswith(f"/{name}")
    assert settings.postgres_db == "keep_my_dev_data"
    engine.dispose.assert_called_once()


def test_runner_does_not_drop_any_database_if_create_fails(monkeypatch):
    monkeypatch.setattr(runner, "get_settings", lambda: Settings(_env_file=None, app_env="test"))
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.side_effect = OperationalError("create", {}, Exception("fixture error"))
    monkeypatch.setattr(runner, "create_engine", lambda *args, **kwargs: engine)
    child = MagicMock()
    monkeypatch.setattr(runner.subprocess, "run", child)

    assert runner.main() == 1
    assert connection.execute.call_count == 1
    assert str(connection.execute.call_args.args[0]).startswith("CREATE DATABASE")
    child.assert_not_called()


def test_runner_refuses_production_before_connecting(monkeypatch):
    monkeypatch.setattr(
        runner,
        "get_settings",
        lambda: Settings(_env_file=None, app_env="production"),
    )
    engine_factory = MagicMock()
    monkeypatch.setattr(runner, "create_engine", engine_factory)
    assert runner.main() == 1
    engine_factory.assert_not_called()
