"""Trusted development import: JSON/JSONL -> shared ingestion service -> PostgreSQL."""

import argparse
import logging
import sys
from contextlib import nullcontext
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy.exc import SQLAlchemyError  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.database import build_engine  # noqa: E402
from app.services.event_files import FileInputError, ingest_file  # noqa: E402
from app.services.event_ingestion import EventIngestionService  # noqa: E402


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--file", type=Path, required=True)
    result.add_argument("--format", choices=("json", "jsonl"), help="Default: infer from extension")
    result.add_argument(
        "--batch-size", type=int, help="Default: 500, or the configured maximum if lower"
    )
    result.add_argument(
        "--rejected-output",
        type=Path,
        help="New JSONL diagnostics file (positions/errors only, no original payload)",
    )
    return result


def main(argv=None):
    arguments = parser()
    args = arguments.parse_args(argv)
    try:
        settings = get_settings()
    except ValidationError:
        print("Configuration invalid. Check the existing .env; no events were imported.")
        return 1
    if settings.app_env not in {"development", "test"}:
        print("The local import utility requires APP_ENV=development or test.")
        return 1
    size = (
        args.batch_size
        if args.batch_size is not None
        else min(500, settings.ingestion_max_batch_size)
    )
    if not 1 <= size <= settings.ingestion_max_batch_size:
        arguments.error("--batch-size must be within INGESTION_MAX_BATCH_SIZE")
    if not args.file.is_file():
        arguments.error("Input file does not exist or is not a regular file")
    if args.rejected_output:
        if args.rejected_output.resolve() == args.file.resolve():
            arguments.error("Rejected output must not be the input file")
        if args.rejected_output.suffix.lower() != ".jsonl":
            arguments.error("Rejected output must use .jsonl")
        if args.rejected_output.exists():
            arguments.error("Rejected output already exists; choose another filename")
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s %(message)s")
    engine = build_engine(settings)
    try:
        if args.rejected_output:
            args.rejected_output.parent.mkdir(parents=True, exist_ok=True)
        report_context = (
            args.rejected_output.open("x", encoding="utf-8", newline="\n")
            if args.rejected_output
            else nullcontext(None)
        )
        with report_context as report, Session(engine) as session:
            result = ingest_file(
                EventIngestionService(session, settings),
                args.file,
                batch_size=size,
                output_format=args.format,
                error_sink=(lambda error: report.write(error.model_dump_json() + "\n"))
                if report
                else None,
            )
        seconds = result.duration_ms / 1000
        print("CyberSentinel Security Event Ingestion")
        print(f"Input file: {args.file}")
        for label, value in (
            ("Events read", result.received),
            ("Valid", result.valid),
            ("Inserted", result.inserted),
            ("Duplicates", result.duplicates),
            ("Invalid", result.invalid),
            ("Failed", result.failed),
        ):
            print(f"{label}: {value:,}")
        print(f"Duration: {seconds:.3f}s")
        print(f"Throughput: {result.received / seconds if seconds else 0:,.0f} events/sec")
        print(f"Complete: {result.complete}")
        for error in result.errors:
            position = f"Line {error.line}" if error.line is not None else f"Record {error.index}"
            print(f"{position}: {error.message}")
        if result.errors_omitted:
            print(f"Additional errors omitted from summary: {result.errors_omitted}")
        if not result.complete:
            print(
                "Stopped at the failed batch; earlier committed batches remain. "
                "Retry is idempotent."
            )
            return 1
        return 2 if result.invalid else 0
    except FileInputError as exc:
        print(str(exc))
        return 2
    except (OSError, SQLAlchemyError) as exc:
        print(
            f"Import interrupted ({type(exc).__name__}). Check files, connectivity and migrations."
        )
        print("Earlier committed batches remain; repeating the import is safe for event IDs.")
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
