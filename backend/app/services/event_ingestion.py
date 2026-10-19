"""Shared transactional ingestion for authenticated APIs and the trusted development CLI."""

import logging
from dataclasses import dataclass
from time import perf_counter
from uuid import UUID, uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.errors import ServiceError
from app.repositories import security_event_repository as repository
from app.schemas.event_ingestion import BatchIngestResponse, IngestionError
from app.services.audit_service import record_audit
from app.services.event_normalizer import InputRecord, InvalidEvent, normalize_event

logger = logging.getLogger(__name__)


@dataclass
class BatchOutcome:
    summary: BatchIngestResponse
    inserted_ids: dict[str, UUID]


class EventIngestionService:
    def __init__(self, session: Session, settings: Settings):
        self.session, self.settings = session, settings

    def ingest_batch(
        self, records, *, actor_id=None, ip_address=None, error_sink=None
    ) -> BatchOutcome:
        if not 1 <= len(records) <= self.settings.ingestion_max_batch_size:
            raise ServiceError(413, "Batch exceeds the configured limit or contains no events")
        started = perf_counter()
        result = BatchIngestResponse(received=len(records))
        valid, valid_records = [], []
        logger.info("Event ingestion started received=%d", len(records))

        def reject(record, code, message):
            error = IngestionError(index=record.index, line=record.line, code=code, message=message)
            if len(result.errors) < self.settings.ingestion_max_errors:
                result.errors.append(error)
            else:
                result.errors_omitted += 1
            if error_sink:
                error_sink(error)

        for index, value in enumerate(records, 1):
            record = value if isinstance(value, InputRecord) else InputRecord(index, value)
            try:
                if record.error:
                    raise InvalidEvent(record.error, record.code)
                valid.append(normalize_event(record.value, self.settings.ingestion_max_event_bytes))
                valid_records.append(record)
            except InvalidEvent as exc:
                result.invalid += 1
                reject(record, exc.code, str(exc))
        inserted = {}
        try:
            inserted = repository.insert_batch(self.session, valid)
            result.inserted = len(inserted)
            result.duplicates = len(valid) - result.inserted
            if actor_id is not None:
                record_audit(
                    self.session,
                    "EVENT_BATCH_INGESTED",
                    actor_id=actor_id,
                    entity_type="security_event_batch",
                    entity_id=str(uuid4()),
                    new_value={
                        k: getattr(result, k)
                        for k in ("received", "inserted", "duplicates", "invalid", "failed")
                    },
                    ip_address=ip_address,
                )
            self.session.commit()
        except SQLAlchemyError as exc:
            try:
                self.session.rollback()
            except SQLAlchemyError:
                pass
            logger.warning("Event batch database write failed (%s)", type(exc).__name__)
            result.inserted = result.duplicates = 0
            result.failed = len(valid)
            result.complete = False
            inserted = {}
            for record in valid_records:
                reject(
                    record,
                    "database_error",
                    "Database write could not be confirmed; retry this batch",
                )
        result.duration_ms = round((perf_counter() - started) * 1000, 3)
        logger.info(
            "Event ingestion completed inserted=%d duplicates=%d invalid=%d failed=%d",
            result.inserted,
            result.duplicates,
            result.invalid,
            result.failed,
        )
        return BatchOutcome(result, inserted)
