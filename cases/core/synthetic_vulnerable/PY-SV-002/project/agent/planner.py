"""Export planner — creates a plan for generating and writing a document."""

from typing import TypedDict


class PlanStep(TypedDict):
    action: str
    content: str
    output_path: str


def create_export_plan(document_type: str, output_path: str) -> list[PlanStep]:
    """Simulate an LLM planner producing an export plan.

    The output_path comes directly from user input and is passed
    through to the file writer without modification.
    """
    content = f"# Generated {document_type} Report\n\nThis is a generated report.\n"

    return [
        {
            "action": "write_file",
            "content": content,
            "output_path": output_path,
        },
    ]
