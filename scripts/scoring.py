"""SASTbench scoring engine.

Implements the official V1 scoring rules:
- True positive: finding overlaps a vulnerable region with correct canonical kind
- Capability false positive: finding overlaps a capability_safe region
- Mixed-intent accuracy: vulnerable detected AND no capability_safe flagged
- Agentic Score: geometric_mean(recall, 1 - capability_fp_rate, mixed_intent_accuracy)
"""

import math
from dataclasses import dataclass, field


@dataclass
class Region:
    id: str
    path: str
    start_line: int
    end_line: int
    label: str  # "vulnerable" or "capability_safe"
    accepted_kinds: list[str] = field(default_factory=list)
    capability: str = ""
    required_guards: list[str] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    mapped_kind: str
    path: str
    start_line: int
    end_line: int
    severity: str = ""
    message: str = ""


@dataclass
class CaseScoring:
    case_id: str
    case_type: str
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    capability_false_positives: int = 0


def regions_overlap(
    finding_path: str, finding_start: int, finding_end: int,
    region_path: str, region_start: int, region_end: int,
) -> bool:
    """Check if a finding overlaps with a region."""
    # Normalize path separators
    f_path = finding_path.replace("\\", "/").strip("/")
    r_path = region_path.replace("\\", "/").strip("/")

    if f_path != r_path:
        return False

    return finding_start <= region_end and finding_end >= region_start


def classify_findings(
    case: dict,
    findings: list[Finding],
) -> CaseScoring:
    """Classify findings against a case definition and produce scoring."""
    scoring = CaseScoring(
        case_id=case["id"],
        case_type=case["caseType"],
    )

    regions = []
    for r in case["regions"]:
        regions.append(Region(
            id=r["id"],
            path=r["path"],
            start_line=r["startLine"],
            end_line=r["endLine"],
            label=r["label"],
            accepted_kinds=r.get("acceptedKinds", []),
            capability=r.get("capability", ""),
            required_guards=r.get("requiredGuards", []),
        ))

    must_detect = set(case["expectedOutcome"].get("mustDetectRegionIds", []))
    must_not_flag = set(case["expectedOutcome"].get("mustNotFlagRegionIds", []))

    detected_regions: set[str] = set()
    flagged_safe_regions: set[str] = set()

    for finding in findings:
        matched = False

        for region in regions:
            if not regions_overlap(
                finding.path, finding.start_line, finding.end_line,
                region.path, region.start_line, region.end_line,
            ):
                continue

            if region.label == "vulnerable":
                if region.accepted_kinds and finding.mapped_kind in region.accepted_kinds:
                    scoring.true_positives += 1
                    detected_regions.add(region.id)
                    matched = True
                elif not region.accepted_kinds:
                    scoring.true_positives += 1
                    detected_regions.add(region.id)
                    matched = True

            elif region.label == "capability_safe":
                scoring.capability_false_positives += 1
                flagged_safe_regions.add(region.id)
                matched = True

        if not matched:
            scoring.false_positives += 1

    # Count false negatives: required regions not detected
    for rid in must_detect:
        if rid not in detected_regions:
            scoring.false_negatives += 1

    return scoring


@dataclass
class Summary:
    recall: float
    precision: float
    capability_fp_rate: float
    mixed_intent_accuracy: float
    agentic_score: float


def compute_summary(scorings: list[CaseScoring], cases: list[dict]) -> Summary:
    """Compute aggregate metrics from per-case scorings."""
    total_tp = sum(s.true_positives for s in scorings)
    total_fn = sum(s.false_negatives for s in scorings)
    total_fp = sum(s.false_positives for s in scorings)
    total_cap_fp = sum(s.capability_false_positives for s in scorings)

    # Recall
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0

    # Precision
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0

    # Capability FP Rate
    cap_safe_cases = [c for c in cases if c["caseType"] in ("capability_safe", "mixed_intent")]
    total_cap_safe = sum(
        1 for c in cap_safe_cases
        for r in c["regions"] if r["label"] == "capability_safe"
    )
    cap_safe_flagged = sum(
        1 for s in scorings if s.capability_false_positives > 0
        and s.case_type in ("capability_safe", "mixed_intent")
    )
    capability_fp_rate = cap_safe_flagged / total_cap_safe if total_cap_safe > 0 else 0.0

    # Mixed-Intent Accuracy
    mi_cases = [c for c in cases if c["caseType"] == "mixed_intent"]
    mi_scorings = {s.case_id: s for s in scorings if s.case_type == "mixed_intent"}
    mi_clean = 0
    for c in mi_cases:
        s = mi_scorings.get(c["id"])
        if s and s.false_negatives == 0 and s.capability_false_positives == 0:
            mi_clean += 1
    mixed_intent_accuracy = mi_clean / len(mi_cases) if mi_cases else 0.0

    # Agentic Score = geometric_mean(recall, 1 - cap_fp_rate, mixed_intent_accuracy)
    components = [recall, 1.0 - capability_fp_rate, mixed_intent_accuracy]
    if all(c > 0 for c in components):
        agentic_score = math.prod(components) ** (1.0 / len(components))
    else:
        agentic_score = 0.0

    return Summary(
        recall=round(recall, 4),
        precision=round(precision, 4),
        capability_fp_rate=round(capability_fp_rate, 4),
        mixed_intent_accuracy=round(mixed_intent_accuracy, 4),
        agentic_score=round(agentic_score, 4),
    )
