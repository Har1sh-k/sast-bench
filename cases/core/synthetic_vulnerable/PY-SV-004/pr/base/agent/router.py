"""Agent router — orchestrates retrieval and test execution."""

from __future__ import annotations

import logging

from agent.retriever import retrieve_context

logger = logging.getLogger(__name__)


def handle_test_request(query: str) -> dict:
    """Handle a test-run request by retrieving context.

    Retrieves relevant context snippets from the knowledge store.
    Test execution is not available in this version.
    """
    if not isinstance(query, str) or not query.strip():
        return {
            "status": "error",
            "message": "Query must be a non-empty string",
        }

    try:
        context_snippets = retrieve_context(query)
    except Exception as exc:
        logger.exception("Failed to retrieve context for query: %s", query)
        return {
            "status": "error",
            "message": f"Context retrieval failed: {exc}",
        }

    if not context_snippets:
        logger.info("No context found for query: %s", query)
        return {
            "status": "skipped",
            "message": "No relevant context found in knowledge store",
        }

    return {
        "status": "skipped",
        "message": "test execution not available",
    }
