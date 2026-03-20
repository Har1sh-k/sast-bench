"""RAG coding assistant configuration."""

import os

KNOWLEDGE_STORE_PATH = os.environ.get(
    "KNOWLEDGE_STORE", "store/knowledge.json"
)
TEST_TIMEOUT = 60
MAX_CONTEXT_SNIPPETS = 5
WORKSPACE_DIR = "/workspace"
