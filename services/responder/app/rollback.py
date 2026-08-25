"""Automatic TTL rollback scheduler for temporary containment actions."""

from __future__ import annotations

import logging
import time
from typing import Any

from .executor import ActionReceipt

logger = logging.getLogger("aegis.rollback")


class RollbackScheduler:
    def __init__(self) -> None:
        self._scheduled_rollbacks: dict[str, dict[str, Any]] = {}

    def schedule(self, receipt: ActionReceipt) -> None:
        if not receipt.reversible or receipt.ttl_seconds <= 0:
            return
        expire_at = time.time() + receipt.ttl_seconds
        self._scheduled_rollbacks[receipt.receipt_id] = {
            "receipt": receipt,
            "expire_at": expire_at,
            "rolled_back": False,
        }
        logger.info("Scheduled automatic rollback for %s in %d seconds", receipt.receipt_id, receipt.ttl_seconds)

    def check_expired(self) -> list[str]:
        now = time.time()
        expired: list[str] = []
        for rid, entry in list(self._scheduled_rollbacks.items()):
            if not entry["rolled_back"] and now >= entry["expire_at"]:
                entry["rolled_back"] = True
                expired.append(rid)
                logger.info("Automatically rolled back expired containment action %s", rid)
        return expired
