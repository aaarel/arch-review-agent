"""Context Compaction, Persistent Session/Vector State, and Async Background Memory."""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import math
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.observability import (
    audit_logger,
    log_agent_outcome_after_callback,
    pii_redactor,
    tracer,
)

try:
    from google.adk.agents.context_cache_config import ContextCacheConfig
    from google.adk.apps.app import EventsCompactionConfig
    from google.adk.apps.llm_event_summarizer import LlmEventSummarizer
    from google.adk.memory import InMemoryMemoryService, VertexAiMemoryBankService
    from google.adk.models import Gemini
    from google.adk.sessions import (
        DatabaseSessionService,
        InMemorySessionService,
        VertexAiSessionService,
    )
    from google.adk.tools.load_memory_tool import LoadMemoryTool
    from google.adk.tools.preload_memory_tool import PreloadMemoryTool
    HAS_ADK_MEMORY = True
except ImportError:  # pragma: no cover
    HAS_ADK_MEMORY = False

    @dataclass
    class EventsCompactionConfig:  # type: ignore[no-redef]
        compaction_interval: int = 6
        overlap_size: int = 2
        token_threshold: int = 12000
        event_retention_size: int = 8
        summarizer: Any = None

    @dataclass
    class ContextCacheConfig:  # type: ignore[no-redef]
        min_tokens: int = 2048
        ttl_seconds: int = 1800
        cache_intervals: int = 10

    LlmEventSummarizer = None  # type: ignore[assignment,misc]
    Gemini = None  # type: ignore[assignment,misc]
    InMemoryMemoryService = None  # type: ignore[assignment,misc]
    VertexAiMemoryBankService = None  # type: ignore[assignment,misc]
    DatabaseSessionService = None  # type: ignore[assignment,misc]
    InMemorySessionService = None  # type: ignore[assignment,misc]
    VertexAiSessionService = None  # type: ignore[assignment,misc]
    LoadMemoryTool = None  # type: ignore[assignment,misc]
    PreloadMemoryTool = None  # type: ignore[assignment,misc]

try:
    from google.cloud import firestore
    HAS_FIRESTORE = True
except ImportError:  # pragma: no cover
    firestore = None  # type: ignore[assignment]
    HAS_FIRESTORE = False

try:
    from google.cloud import discoveryengine_v1
    HAS_VERTEX_SEARCH = True
except ImportError:  # pragma: no cover
    discoveryengine_v1 = None  # type: ignore[assignment]
    HAS_VERTEX_SEARCH = False

_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def build_events_compaction_config(summarizer_model: str = "gemini-2.5-flash") -> EventsCompactionConfig:
    """Create ADK `EventsCompactionConfig` with LLM event summarization to curb context bloat."""
    summarizer = (
        LlmEventSummarizer(llm=Gemini(model=summarizer_model))
        if HAS_ADK_MEMORY and LlmEventSummarizer and Gemini
        else None
    )
    kwargs: dict[str, Any] = {"compaction_interval": 6, "overlap_size": 2}
    if summarizer is not None:
        kwargs["summarizer"] = summarizer
    return EventsCompactionConfig(**kwargs)


def build_context_cache_config() -> ContextCacheConfig:
    """Create ADK `ContextCacheConfig` to reuse system constitutions and control catalogs."""
    return ContextCacheConfig(min_tokens=2048, ttl_seconds=1800, cache_intervals=10)


@functools.cache
def create_persistent_session_service() -> Any:
    """Instantiate persistent session backend (DatabaseSessionService or VertexAiSessionService)."""
    if not HAS_ADK_MEMORY:
        return None
    db_url = os.environ.get("SESSION_DB_URL")
    if db_url:
        return DatabaseSessionService(db_url=db_url)
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    agent_engine_id = os.environ.get("AGENT_ENGINE_ID")
    if project_id and agent_engine_id:
        return VertexAiSessionService(
            project=project_id,
            location=os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1"),
            agent_engine_id=agent_engine_id,
        )
    return InMemorySessionService()


@functools.cache
def create_persistent_memory_service() -> Any:
    """Instantiate cross-session long-term memory backend (`VertexAiMemoryBankService`)."""
    if not HAS_ADK_MEMORY:
        return None
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    agent_engine_id = os.environ.get("AGENT_ENGINE_ID")
    if project_id and agent_engine_id:
        return VertexAiMemoryBankService(
            project=project_id,
            location=os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1"),
            agent_engine_id=agent_engine_id,
        )
    return InMemoryMemoryService()


def get_memory_retrieval_tools() -> list[Any]:
    """Return ADK memory retrieval tools (`PreloadMemoryTool`, `LoadMemoryTool`)."""
    if HAS_ADK_MEMORY and PreloadMemoryTool and LoadMemoryTool:
        return [PreloadMemoryTool(), LoadMemoryTool()]
    return []


@dataclass
class ConversationTurn:
    """Single PII-scrubbed conversational turn stored in persistent session state."""

    role: str
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    estimated_tokens: int = 0
    pinned: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.content = pii_redactor.redact_text(self.content)
        self.metadata = pii_redactor.redact_payload(self.metadata)
        if self.estimated_tokens <= 0:
            self.estimated_tokens = max(1, math.ceil(len(self.content) / 4))


class HistoryCompactor:
    """Prevents context bloat via sliding windows, progressive summarization, and token budgets."""

    def __init__(self, max_context_tokens: int = 4096, sliding_window_turns: int = 6) -> None:
        self.max_context_tokens = max_context_tokens
        self.sliding_window_turns = sliding_window_turns
        self.adk_compaction_config = build_events_compaction_config()
        self.adk_context_cache_config = build_context_cache_config()

    @staticmethod
    def estimate_tokens(turns: list[ConversationTurn]) -> int:
        return sum(t.estimated_tokens for t in turns)

    @staticmethod
    def summarize_turns(evicted: list[ConversationTurn]) -> ConversationTurn:
        snippets = [f"[{t.role.upper()}] {t.content.replace(chr(10), ' ')[:100]}" for t in evicted]
        return ConversationTurn(
            role="system",
            content="COMPACTED_HISTORY_SUMMARY: " + " | ".join(snippets),
            pinned=True,
            metadata={"compacted_turn_count": len(evicted)},
        )

    def compact_history(self, turns: list[ConversationTurn]) -> list[ConversationTurn]:
        """Compact chronological turns to fit within `max_context_tokens` while keeping pinned turns."""
        with tracer.start_span("memory.compact_history", {"initial_turns": len(turns)}):
            if not turns:
                return []
            pinned = [t for t in turns if t.pinned]
            unpinned = [t for t in turns if not t.pinned]
            summaries: list[ConversationTurn] = []

            if len(unpinned) > self.sliding_window_turns:
                evicted = unpinned[: -self.sliding_window_turns]
                unpinned = unpinned[-self.sliding_window_turns :]
                summaries.append(self.summarize_turns(evicted))

            candidate = pinned + summaries + unpinned
            while self.estimate_tokens(candidate) > self.max_context_tokens and unpinned:
                dropped = unpinned.pop(0)
                summaries = [self.summarize_turns(summaries + [dropped])]
                candidate = pinned + summaries + unpinned

            if self.estimate_tokens(candidate) > self.max_context_tokens and summaries:
                budget = max(1, self.max_context_tokens - self.estimate_tokens(pinned + unpinned))
                summaries[0] = ConversationTurn(
                    role="system",
                    content=summaries[0].content[: budget * 4],
                    estimated_tokens=budget,
                    pinned=True,
                    metadata=summaries[0].metadata,
                )
                candidate = pinned + summaries + unpinned
            return candidate


class PersistentSessionStore:
    """Persistent cross-turn session & vector store (Firestore + Vertex AI Search + SQLite Vector)."""

    def __init__(self, sqlite_path: str = ":memory:", compactor: HistoryCompactor | None = None) -> None:
        self.sqlite_path = sqlite_path
        self.compactor = compactor or HistoryCompactor()
        self.project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        self._conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
        self._init_tables()
        self._firestore = self._init_firestore()

    def _init_firestore(self) -> Any:
        if HAS_FIRESTORE and self.project_id and os.environ.get("ENABLE_FIRESTORE_SESSIONS", "false").lower() == "true":
            try:
                return firestore.Client(project=self.project_id)
            except Exception:  # pragma: no cover
                return None
        return None

    def _init_tables(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS session_turns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL,
                timestamp TEXT NOT NULL, estimated_tokens INTEGER NOT NULL,
                pinned INTEGER NOT NULL DEFAULT 0, metadata_json TEXT NOT NULL
            )"""
        )
        cur.execute(
            """CREATE TABLE IF NOT EXISTS vector_memory_bank (
                memory_id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
                summary_text TEXT NOT NULL, embedding_json TEXT NOT NULL, created_at TEXT NOT NULL
            )"""
        )
        self._conn.commit()

    @staticmethod
    def embed_text(text: str, dims: int = 16) -> list[float]:
        """Compute normalized deterministic vector embedding for local semantic memory search."""
        vec = [0.0] * dims
        for tok in text.lower().split():
            digest = hashlib.sha256(tok.encode("utf-8")).digest()
            for i in range(dims):
                vec[i] += (digest[i] / 255.0) - 0.5
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [round(v / norm, 6) for v in vec]

    def append_turn(self, session_id: str, turn: ConversationTurn) -> list[ConversationTurn]:
        """Persist a redacted turn, mirror to Firestore if configured, and compact if needed."""
        with tracer.start_span("memory.append_turn", {"session.id": session_id, "role": turn.role}):
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO session_turns (session_id, role, content, timestamp, estimated_tokens, pinned, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session_id, turn.role, turn.content, turn.timestamp, turn.estimated_tokens, int(turn.pinned), json.dumps(turn.metadata)),
            )
            self._conn.commit()
            if self._firestore is not None:
                try:
                    self._firestore.collection("arb_sessions").document(session_id).set(
                        {"updated_at": turn.timestamp, "last_role": turn.role, "last_content": turn.content},
                        merge=True,
                    )
                except Exception:  # pragma: no cover
                    pass
            raw = self.get_turns(session_id)
            compacted = self.compactor.compact_history(raw)
            if len(compacted) != len(raw):
                self._replace_turns(session_id, compacted)
            return compacted

    def _replace_turns(self, session_id: str, turns: list[ConversationTurn]) -> None:
        cur = self._conn.cursor()
        cur.execute("DELETE FROM session_turns WHERE session_id = ?", (session_id,))
        for t in turns:
            cur.execute(
                "INSERT INTO session_turns (session_id, role, content, timestamp, estimated_tokens, pinned, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session_id, t.role, t.content, t.timestamp, t.estimated_tokens, int(t.pinned), json.dumps(t.metadata)),
            )
        self._conn.commit()

    def get_turns(self, session_id: str) -> list[ConversationTurn]:
        rows = self._conn.execute(
            "SELECT role, content, timestamp, estimated_tokens, pinned, metadata_json FROM session_turns WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        ).fetchall()
        return [
            ConversationTurn(role=r[0], content=r[1], timestamp=r[2], estimated_tokens=r[3], pinned=bool(r[4]), metadata=json.loads(r[5]))
            for r in rows
        ]

    def store_vector_memory(self, session_id: str, memory_id: str, summary_text: str) -> dict[str, Any]:
        """Persist a PII-scrubbed consolidated memory record with its vector embedding."""
        clean = pii_redactor.redact_text(summary_text)
        emb = self.embed_text(clean)
        now = datetime.now(UTC).isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO vector_memory_bank (memory_id, session_id, summary_text, embedding_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (memory_id, session_id, clean, json.dumps(emb), now),
        )
        self._conn.commit()
        return {"memory_id": memory_id, "session_id": session_id, "summary_text": clean, "dims": len(emb), "created_at": now}

    def search_vector_memories(self, query: str, top_k: int = 3, session_id: str | None = None) -> list[dict[str, Any]]:
        """Retrieve semantically similar past reviews via Vertex AI Search or local vector cosine similarity."""
        data_store = os.environ.get("VERTEX_SEARCH_DATA_STORE_ID")
        if HAS_VERTEX_SEARCH and data_store:  # pragma: no cover - requires live GCP datastore
            try:
                client = discoveryengine_v1.SearchServiceClient()
                resp = client.search(request={"serving_config": f"{data_store}/servingConfigs/default_search", "query": query, "page_size": top_k})
                return [{"memory_id": r.id, "summary_text": str(r.document.derived_struct_data), "source": "vertex_ai_search"} for r in resp.results]
            except Exception:
                pass

        q_vec = self.embed_text(query)
        sql = "SELECT memory_id, session_id, summary_text, embedding_json, created_at FROM vector_memory_bank"
        params: tuple[Any, ...] = ()
        if session_id:
            sql += " WHERE session_id = ?"
            params = (session_id,)
        scored: list[tuple[float, dict[str, Any]]] = []
        for mid, sid, txt, emb_json, ts in self._conn.execute(sql, params).fetchall():
            emb = json.loads(emb_json)
            sim = sum(a * b for a, b in zip(q_vec, emb, strict=True))
            scored.append((sim, {"memory_id": mid, "session_id": sid, "summary_text": txt, "similarity": round(sim, 4), "created_at": ts}))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored[:top_k]]


class AsyncMemoryConsolidator:
    """Runs expensive memory summarization and vector indexing as non-blocking `asyncio` tasks."""

    def __init__(self, store: PersistentSessionStore) -> None:
        self.store = store
        self._tasks: list[asyncio.Task[Any]] = []

    async def consolidate_session_async(self, session_id: str, turns: list[ConversationTurn] | None = None) -> dict[str, Any]:
        """Asynchronously consolidate recent turns into long-term vector memory without blocking UI."""
        with tracer.start_span("memory.async_consolidate", {"session.id": session_id}):
            corr_id = audit_logger.log_intent(
                action_type="ASYNC_MEMORY",
                target_name="consolidate_session_async",
                intended_inputs={"session_id": session_id},
                rationale="Consolidate session history into vector memory in background task.",
            )
            await asyncio.sleep(0)  # Yield to event loop so user response streams immediately
            active = turns if turns is not None else self.store.get_turns(session_id)
            digest = hashlib.sha256(f"{session_id}:{len(active)}".encode()).hexdigest()[:10]
            summary = f"ARB Session {session_id} ({len(active)} turns): " + "; ".join(
                f"{t.role}: {t.content[:75]}" for t in active[-3:]
            )
            record = self.store.store_vector_memory(session_id, f"mem-{digest}", summary)
            audit_logger.log_outcome(
                correlation_id=corr_id,
                action_type="ASYNC_MEMORY",
                target_name="consolidate_session_async",
                actual_status="success",
                actual_output=record,
                duration_ms=1.0,
            )
            return record

    def schedule_background_consolidation(self, session_id: str, turns: list[ConversationTurn] | None = None) -> asyncio.Task[dict[str, Any]]:
        """Dispatch memory consolidation via `asyncio.create_task`."""
        task = asyncio.create_task(self.consolidate_session_async(session_id, turns))
        self._tasks.append(task)
        _BACKGROUND_TASKS.add(task)
        task.add_done_callback(_BACKGROUND_TASKS.discard)
        return task

    async def flush(self) -> list[dict[str, Any]]:
        """Await all pending background tasks (for tests and graceful shutdown)."""
        pending = list(self._tasks)
        self._tasks.clear()
        return list(await asyncio.gather(*pending)) if pending else []


async def async_after_agent_memory_callback(callback_context: Any) -> None:
    """ADK after_agent_callback scheduling background Memory Bank consolidation without blocking."""
    log_agent_outcome_after_callback(callback_context)

    async def _persist() -> None:
        add_fn = getattr(callback_context, "add_session_to_memory", None)
        if callable(add_fn):
            try:
                await add_fn()
            except Exception:  # pragma: no cover
                pass

    try:
        task = asyncio.create_task(_persist())
        _BACKGROUND_TASKS.add(task)
        task.add_done_callback(_BACKGROUND_TASKS.discard)
    except RuntimeError:  # pragma: no cover - no running event loop
        pass


default_compactor = HistoryCompactor()
default_session_store = PersistentSessionStore(compactor=default_compactor)
default_async_memory = AsyncMemoryConsolidator(store=default_session_store)
