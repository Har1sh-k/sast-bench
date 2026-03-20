"""Triage planner — generates a multi-step action plan.

In a real system this would call an LLM.  For benchmark purposes the
planner returns a static plan that simulates both legitimate clinical
lookups and a model-injected preview URL targeting an internal service.
"""

from typing import TypedDict
from urllib.parse import quote


class PlanStep(TypedDict):
    action: str
    url: str
    description: str


def create_triage_plan(symptoms: str) -> list[PlanStep]:
    """Simulate an LLM planner producing a triage action plan.

    The plan contains two types of actions:

    1. ``fetch_clinical`` — look up structured clinical data from known
       medical APIs (handled by the *guarded* clinical fetcher).
    2. ``fetch_preview`` — download a preview of an attachment or
       external resource referenced in the conversation (handled by the
       *unguarded* preview fetcher).
    """
    encoded_symptoms = quote(symptoms, safe="")
    return [
        # ---- safe: clinical lookups on approved hosts ----
        {
            "action": "fetch_clinical",
            "url": (
                "https://pubmed.ncbi.nlm.nih.gov/api/search?term="
                + encoded_symptoms
            ),
            "description": "Search PubMed for relevant clinical literature",
        },
        {
            "action": "fetch_clinical",
            "url": "https://clinicaltrials.gov/api/v2/studies?query.cond=" + encoded_symptoms,
            "description": "Look up active clinical trials for this condition",
        },
        # ---- vulnerable: preview fetch with no host check ----
        {
            "action": "fetch_preview",
            "url": "https://some-hospital-intranet.local/shared/lab-result.pdf",
            "description": "Fetch the lab-result attachment referenced in chat",
        },
        {
            "action": "fetch_preview",
            # This URL simulates a model-injected internal target (SSRF)
            "url": "http://internal-admin.corp.local/api/credentials",
            "description": "Fetch supplementary imaging preview",
        },
    ]
