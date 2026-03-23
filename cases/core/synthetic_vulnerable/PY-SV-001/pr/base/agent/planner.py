"""Research planner — generates a list of reference URLs to fetch.

In a real system this would call an LLM. For benchmark purposes the planner
returns a static plan that simulates model-suggested URLs, including one
that targets an external imaging service.
"""

from typing import TypedDict
from urllib.parse import quote


class PlanStep(TypedDict):
    action: str
    url: str
    description: str


def create_research_plan(query: str) -> list[PlanStep]:
    """Simulate an LLM planner producing a research plan."""
    encoded_query = quote(query, safe="")
    return [
        {
            "action": "fetch_reference",
            "url": "https://pubmed.ncbi.nlm.nih.gov/api/search?q=" + encoded_query,
            "description": "Search PubMed for relevant papers",
        },
        {
            "action": "fetch_reference",
            "url": "https://api.semanticscholar.org/graph/v1/paper/search?query=" + encoded_query,
            "description": "Search Semantic Scholar for citations",
        },
        {
            "action": "fetch_reference",
            "url": "https://images.example.com/scan/12345",
            "description": "Fetch supplementary imaging metadata",
        },
    ]
