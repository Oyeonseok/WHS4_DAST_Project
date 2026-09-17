"""Compatibility exports for persisted Validation.db version 1."""

from .legacy.store import (
    initialize_store,
    persist_decision,
    read_verified_validation,
    validation_status,
)

__all__ = [
    "initialize_store",
    "persist_decision",
    "read_verified_validation",
    "validation_status",
]
