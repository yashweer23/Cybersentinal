import os

# Non-secret defaults for Phase 1 unit tests. Integration tests use their own explicit URL.
os.environ["POSTGRES_PASSWORD"] = "test-fixture-not-a-real-secret"
os.environ["APP_ENV"] = "test"
os.environ["JWT_SECRET_KEY"] = "test-only-jwt-fixture-with-more-than-thirty-two-bytes"

pytest_plugins = ["tests.database_fixtures"]
