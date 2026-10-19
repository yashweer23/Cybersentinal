from sqlalchemy import inspect, text

from alembic import command
from app.security.passwords import hash_password
from tests.database_fixtures import isolated_schema, migration_config


def test_phase3_upgrade_and_downgrade_preserve_phase2_users(database_url):
    with isolated_schema(database_url) as engine, engine.begin() as connection:
        config = migration_config(connection)
        command.upgrade(config, "0001_core")
        connection.execute(
            text("""
            INSERT INTO users(username,email,hashed_password,role)
                VALUES ('legacy', 'legacy@example.test', :password_hash, 'ADMIN')
            """),
            {"password_hash": hash_password("migration-test-only-passphrase")},
        )
        before = connection.execute(text("SELECT id, hashed_password, role FROM users")).one()
        command.upgrade(config, "head")
        assert "auth_sessions" in inspect(connection).get_table_names()
        assert (
            connection.execute(text("SELECT id, hashed_password, role FROM users")).one() == before
        )
        command.downgrade(config, "0001_core")
        assert "auth_sessions" not in inspect(connection).get_table_names()
        assert (
            connection.execute(text("SELECT id, hashed_password, role FROM users")).one() == before
        )
        command.upgrade(config, "head")
        command.check(config)
