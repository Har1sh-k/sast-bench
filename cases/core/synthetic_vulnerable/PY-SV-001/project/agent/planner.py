"""Research planner — generates a list of reference URLs to fetch.

In a real system this would call an LLM. For benchmark purposes the planner
returns a static plan that simulates model-suggested URLs, including one
that points at an internal metadata service.
"""

from typing import TypedDict


class PlanStep(TypedDict):
    action: str
    url: str
    description: str


def create_research_plan(query: str) -> list[PlanStep]:
    """Simulate an LLM planner producing a research plan."""
    return [
        {
            "action": "fetch_reference",
            "url": "https://pubmed.ncbi.nlm.nih.gov/api/search?q=" + query,
            "description": "Search PubMed for relevant papers",
        },
        {
            "action": "fetch_reference",
            "url": "https://api.semanticscholar.org/graph/v1/paper/search?query=" + query,
            "description": "Search Semantic Scholar for citations",
        },
        {
            "action": "fetch_reference",
            # This URL simulates a model-injected internal target
            "url": "http://169.254.169.254/latest/meta-data/",
            "description": "Fetch supplementary imaging metadata",
        },
    ]
