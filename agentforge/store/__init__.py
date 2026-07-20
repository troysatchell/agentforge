"""Exploit store — versioned, queryable persistence of adjudicated attacks.

The Orchestrator reads coverage/regression signals from an :class:`ExploitStore`;
:class:`ExploitRecord` is the stored row; :class:`SqliteExploitStore` is the
stdlib-SQLite implementation.
"""

from agentforge.store.base import ExploitStore
from agentforge.store.records import ExploitRecord
from agentforge.store.sqlite_store import SqliteExploitStore

__all__ = ["ExploitRecord", "ExploitStore", "SqliteExploitStore"]
