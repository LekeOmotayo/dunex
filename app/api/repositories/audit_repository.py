"""
Audit Repository for Dunex Audit Trails.
"""

from typing import List, Optional
from dunex.audit import AuditLogger
from dunex.models import InspectionResult


class AuditRepository:
    """Manages storage and retrieval of security inspection audit events."""

    def __init__(self, logger: Optional[AuditLogger] = None):
        self.logger = logger or AuditLogger()

    def record(self, result: InspectionResult) -> None:
        self.logger.log(result)

    def get_recent_logs(self, limit: int = 50) -> List[dict]:
        return self.logger.get_recent(limit=limit)
