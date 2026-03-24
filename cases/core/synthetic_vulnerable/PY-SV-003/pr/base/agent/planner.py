"""Task planner — parses user messages into structured task objects.

In a real system this would call an LLM. For benchmark purposes the planner
returns structured tasks derived from the user's message text.
"""

from __future__ import annotations

from typing import TypedDict


class Task(TypedDict):
    action: str
    name: str
    description: str


def parse_tasks(user_message: str) -> list[Task]:
    """Parse a user message into a list of structured tasks.

    The planner extracts task intent from the user's natural-language
    message. Each task gets an action type, a short name, and the
    original description text.
    """
    if not isinstance(user_message, str) or not user_message.strip():
        raise ValueError("User message must be a non-empty string")

    # Simulate structured task extraction from natural language.
    # In production this would be an LLM call.
    return [
        {
            "action": "execute_task",
            "name": "user_task",
            "description": user_message.strip(),
        },
    ]
