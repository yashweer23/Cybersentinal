from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, Numeric, String, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.common import JSON_OBJECT, UUIDPrimaryKey


class SystemMetric(UUIDPrimaryKey, Base):
    __tablename__ = "system_metrics"
    __table_args__ = (
        Index("ix_system_metrics_name_timestamp", "metric_name", "timestamp"),
        CheckConstraint("jsonb_typeof(metadata) = 'object'", name="metadata_object"),
        CheckConstraint("metric_value <> 'NaN'::numeric", name="metric_value_finite"),
    )

    metric_name: Mapped[str] = mapped_column(String(100))
    metric_value: Mapped[Decimal] = mapped_column(Numeric(20, 6))
    unit: Mapped[str] = mapped_column(String(32))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # DeclarativeBase.metadata is reserved. The PostgreSQL column is still named metadata.
    metric_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSON_OBJECT,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
