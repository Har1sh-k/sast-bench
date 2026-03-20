"""Agent router — orchestrates retrieval and test execution."""

from __future__ import annotations

import logging

from agent.retriever import retrieve_context
from tools.test_runner import run_tests

logger = logging.getLogger(__name__)


def handle_test_request(query: str) -> dict:
    """Handle a test-run request by retrieving context and executing tests.

    Retrieves relevant context snippets from the knowledge store, then
    passes them to the test runner tool to construct and execute the
    appropriate test command.
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

    try:
        result = run_tests(context_snippets)
    except Exception as exc:
        logger.exception("Unhandled error running tests")
        result = {
            "status": "error",
            "message": f"Internal error: {exc}",
        }

    return result
