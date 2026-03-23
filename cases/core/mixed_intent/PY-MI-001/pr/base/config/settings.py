"""Triage assistant configuration."""

# Hosts pre-approved by the security team for clinical data retrieval.
# Using frozenset for immutability and O(1) lookup.
APPROVED_CLINICAL_HOSTS: frozenset[str] = frozenset([
    "pubmed.ncbi.nlm.nih.gov",
    "clinicaltrials.gov",
    "api.fda.gov",
    "loinc.org",
])

# General settings
REQUEST_TIMEOUT = 15
MAX_PREVIEW_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
USER_AGENT = "MedTriageAssistant/1.0"
