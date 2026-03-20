"""Context retriever — reads relevant snippets from the knowledge store.

This module reads from the local JSON knowledge store and returns
matching context snippets for a given query. The retriever itself
is not vulnerable; it faithfully returns whatever data is in the store.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from config.settings import KNOWLEDGE_STORE_PATH, MAX_CONTEXT_SNIPPETS

logger = logging.getLogger(__name__)


def load_knowledge_store() -> list[dict]:
    """Load all entries from the knowledge store JSON file."""
    store_path = Path(KNOWLEDGE_STORE_PATH)

    if not store_path.is_file():
        logger.warning("Knowledge store not found at %s", store_path)
        return []

    try:
        with store_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to load knowledge store: %s", exc)
        return []

    if not isinstance(data, list):
        logger.error("Knowledge store root must be a JSON array")
        return []

    return data


def retrieve_context(query: str) -> list[str]:
    """Retrieve context snippets relevant to the query.

    Returns a list of content strings from knowledge store entries
    whose topic matches any word in the query. In a real system this
    would use vector similarity; here we use simple keyword matching.
    """
    if not isinstance(query, str) or not query.strip():
        return []

    entries = load_knowledge_store()
    query_words = set(query.lower().split())

    matches: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        topic = entry.get("topic", "")
        content = entry.get("content", "")
        if not isinstance(topic, str) or not isinstance(content, str):
            continue
        if topic.lower() in query_words:
            matches.append(content)
        if len(matches) >= MAX_CONTEXT_SNIPPETS:
            break

    return matches
