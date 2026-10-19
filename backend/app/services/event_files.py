"""Bounded JSON files and streamed JSONL records; no HTTP upload or arbitrary URL fetches."""

from pathlib import Path
from time import perf_counter

from app.config import Settings
from app.core.event_validation import strict_json
from app.schemas.event_ingestion import BatchIngestResponse
from app.services.event_ingestion import EventIngestionService
from app.services.event_normalizer import InputRecord


class FileInputError(ValueError):
    pass


def read_records(path: Path, settings: Settings, output_format: str | None = None):
    kind = output_format or path.suffix.lower().removeprefix(".")
    if kind not in {"json", "jsonl"}:
        raise FileInputError("Use a .json/.jsonl file or explicitly choose --format json/jsonl")
    with path.open("rb") as handle:
        if kind == "json":
            content = handle.read(settings.ingestion_max_json_file_bytes + 1)
            if len(content) > settings.ingestion_max_json_file_bytes:
                raise FileInputError("JSON file exceeds the configured limit; use streaming JSONL")
            try:
                data = strict_json(content.decode("utf-8-sig"))
            except (ValueError, UnicodeError, RecursionError):
                raise FileInputError(
                    "Invalid UTF-8 JSON document; no events were imported"
                ) from None
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                raise FileInputError("JSON file must contain an event object or an array of events")
            for index, value in enumerate(data, 1):
                yield InputRecord(index, value)
            return
        line_number = record_index = 0
        while True:
            line = handle.readline(settings.ingestion_max_event_bytes + 1)
            if not line:
                break
            line_number += 1
            if len(line) > settings.ingestion_max_event_bytes:
                # Discard the rest of this physical line in bounded chunks; resume at the next.
                while not line.endswith(b"\n"):
                    line = handle.readline(settings.ingestion_max_event_bytes + 1)
                    if not line:
                        break
                record_index += 1
                yield InputRecord(
                    record_index,
                    line=line_number,
                    error="JSONL record exceeds the configured byte limit",
                    code="record_too_large",
                )
                continue
            if line_number == 1:
                line = line.removeprefix(b"\xef\xbb\xbf")
            if not line.strip():
                continue
            record_index += 1
            try:
                data = strict_json(line.decode("utf-8"))
            except (ValueError, UnicodeError, RecursionError):
                yield InputRecord(record_index, line=line_number, error="Invalid UTF-8 JSON record")
                continue
            yield InputRecord(record_index, data, line_number)


def ingest_file(
    service: EventIngestionService,
    path: Path,
    *,
    batch_size: int = 500,
    output_format: str | None = None,
    error_sink=None,
) -> BatchIngestResponse:
    if not 1 <= batch_size <= service.settings.ingestion_max_batch_size:
        raise FileInputError("Batch size must be within INGESTION_MAX_BATCH_SIZE")
    started = perf_counter()
    result = BatchIngestResponse()
    batch = []

    def flush():
        outcome = service.ingest_batch(batch, error_sink=error_sink).summary
        for field in ("received", "inserted", "duplicates", "invalid", "failed"):
            setattr(result, field, getattr(result, field) + getattr(outcome, field))
        available = service.settings.ingestion_max_errors - len(result.errors)
        result.errors.extend(outcome.errors[:available])
        result.errors_omitted += outcome.errors_omitted + max(0, len(outcome.errors) - available)
        result.complete = outcome.complete
        batch.clear()

    for record in read_records(path, service.settings, output_format):
        batch.append(record)
        if len(batch) == batch_size:
            flush()
            if not result.complete:
                break
    if batch and result.complete:
        flush()
    result.duration_ms = round((perf_counter() - started) * 1000, 3)
    return result
