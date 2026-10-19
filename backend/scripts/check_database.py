"""Run from backend: python -m scripts.check_database"""

from sqlalchemy import text

from app.config import get_settings
from app.database import build_engine


def main() -> None:
    engine = build_engine(get_settings())
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar_one() == 1
        print("PostgreSQL connected: SELECT 1 succeeded")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
