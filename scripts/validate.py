"""SASTbench case validator.

Validates all case.json files against the case schema and checks
that referenced files and line ranges exist.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema" / "case.schema.json"
CASES_DIR = REPO_ROOT / "cases"

VALID_SCHEMA_VERSIONS = {"1.0.0"}
VALID_TRACKS = {"core", "full"}
VALID_CASE_TYPES = {
    "synthetic_vulnerable",
    "capability_safe",
    "mixed_intent",
    "real_world_disclosed",
}
VALID_LANGUAGES = {"python", "typescript", "rust"}
VALID_KINDS = {"command_injection", "path_traversal", "ssrf"}
VALID_LABELS = {"vulnerable", "capability_safe"}
VALID_CAPABILITIES = {"code_execution", "filesystem", "network"}
VALID_GUARDS = {"allowlist", "workspace_root", "host_allowlist", "scheme_allowlist"}


class ValidationError:
    def __init__(self, case_id: str, message: str):
        self.case_id = case_id
        self.message = message

    def __str__(self) -> str:
        return f"[{self.case_id}] {self.message}"


def validate_case(case_dir: Path) -> list[ValidationError]:
    """Validate a single case directory."""
    errors: list[ValidationError] = []
    case_file = case_dir / "case.json"
    case_id = case_dir.name

    if not case_file.exists():
        errors.append(ValidationError(case_id, "Missing case.json"))
        return errors

    try:
        with open(case_file) as f:
            case = json.load(f)
    except json.JSONDecodeError as e:
        errors.append(ValidationError(case_id, f"Invalid JSON: {e}"))
        return errors

    # Required fields
    for field in [
        "schemaVersion", "id", "track", "caseType", "language",
        "canonicalKind", "files", "regions", "expectedOutcome",
    ]:
        if field not in case:
            errors.append(ValidationError(case_id, f"Missing required field: {field}"))

    if errors:
        return errors

    # Enum validations
    if case["schemaVersion"] not in VALID_SCHEMA_VERSIONS:
        errors.append(ValidationError(case_id, f"Invalid schemaVersion: {case['schemaVersion']}"))
    if case["track"] not in VALID_TRACKS:
        errors.append(ValidationError(case_id, f"Invalid track: {case['track']}"))
    if case["caseType"] not in VALID_CASE_TYPES:
        errors.append(ValidationError(case_id, f"Invalid caseType: {case['caseType']}"))
    if case["language"] not in VALID_LANGUAGES:
        errors.append(ValidationError(case_id, f"Invalid language: {case['language']}"))
    if case["canonicalKind"] not in VALID_KINDS:
        errors.append(ValidationError(case_id, f"Invalid canonicalKind: {case['canonicalKind']}"))

    # Files root must exist
    root = case["files"].get("root", "")
    root_path = case_dir / root
    if not root_path.exists():
        errors.append(ValidationError(case_id, f"Files root does not exist: {root}"))

    # Validate regions
    region_ids = set()
    for region in case["regions"]:
        rid = region.get("id", "<missing>")

        if rid in region_ids:
            errors.append(ValidationError(case_id, f"Duplicate region ID: {rid}"))
        region_ids.add(rid)

        if region.get("label") not in VALID_LABELS:
            errors.append(ValidationError(case_id, f"Region {rid}: invalid label: {region.get('label')}"))

        if "capability" in region and region["capability"] not in VALID_CAPABILITIES:
            errors.append(ValidationError(case_id, f"Region {rid}: invalid capability: {region['capability']}"))

        if "requiredGuards" in region:
            for guard in region["requiredGuards"]:
                if guard not in VALID_GUARDS:
                    errors.append(ValidationError(case_id, f"Region {rid}: invalid guard: {guard}"))

        if "acceptedKinds" in region:
            for kind in region["acceptedKinds"]:
                if kind not in VALID_KINDS:
                    errors.append(ValidationError(case_id, f"Region {rid}: invalid accepted kind: {kind}"))

        # Check file exists and line range is valid
        region_path = case_dir / region.get("path", "")
        if not region_path.exists():
            errors.append(ValidationError(case_id, f"Region {rid}: file does not exist: {region.get('path')}"))
        else:
            line_count = len(region_path.read_text(encoding="utf-8").splitlines())
            start = region.get("startLine", 0)
            end = region.get("endLine", 0)
            if start < 1 or end < 1:
                errors.append(ValidationError(case_id, f"Region {rid}: line numbers must be >= 1"))
            elif start > end:
                errors.append(ValidationError(case_id, f"Region {rid}: startLine ({start}) > endLine ({end})"))
            elif end > line_count:
                errors.append(ValidationError(case_id, f"Region {rid}: endLine ({end}) exceeds file length ({line_count})"))

    # Validate expectedOutcome references
    outcome = case["expectedOutcome"]
    for rid in outcome.get("mustDetectRegionIds", []):
        if rid not in region_ids:
            errors.append(ValidationError(case_id, f"mustDetectRegionIds references unknown region: {rid}"))
    for rid in outcome.get("mustNotFlagRegionIds", []):
        if rid not in region_ids:
            errors.append(ValidationError(case_id, f"mustNotFlagRegionIds references unknown region: {rid}"))

    # Case type consistency checks
    case_type = case["caseType"]
    if case_type == "capability_safe":
        if outcome.get("mustDetectRegionIds"):
            errors.append(ValidationError(case_id, "capability_safe case should have empty mustDetectRegionIds"))
        safe_regions = [r for r in case["regions"] if r["label"] == "capability_safe"]
        if not safe_regions:
            errors.append(ValidationError(case_id, "capability_safe case must have at least one capability_safe region"))

    if case_type == "mixed_intent":
        safe_regions = [r for r in case["regions"] if r["label"] == "capability_safe"]
        vuln_regions = [r for r in case["regions"] if r["label"] == "vulnerable"]
        if not safe_regions:
            errors.append(ValidationError(case_id, "mixed_intent case must have at least one capability_safe region"))
        if not vuln_regions:
            errors.append(ValidationError(case_id, "mixed_intent case must have at least one vulnerable region"))

    if case_type == "synthetic_vulnerable":
        vuln_regions = [r for r in case["regions"] if r["label"] == "vulnerable"]
        if not vuln_regions:
            errors.append(ValidationError(case_id, "synthetic_vulnerable case must have at least one vulnerable region"))

    if case_type == "real_world_disclosed" and "realWorld" not in case:
        errors.append(ValidationError(case_id, "real_world_disclosed case must have realWorld metadata"))

    # Context file should exist
    if not (case_dir / "context.md").exists():
        errors.append(ValidationError(case_id, "Missing context.md"))

    return errors


def find_cases(base_dir: Path) -> list[Path]:
    """Find all case directories under the given base."""
    cases = []
    for case_json in sorted(base_dir.rglob("case.json")):
        cases.append(case_json.parent)
    return cases


def main() -> int:
    cases = find_cases(CASES_DIR)
    if not cases:
        print("No cases found.")
        return 1

    all_errors: list[ValidationError] = []
    for case_dir in cases:
        errors = validate_case(case_dir)
        all_errors.extend(errors)

    print(f"Validated {len(cases)} cases.")

    if all_errors:
        print(f"\n{len(all_errors)} error(s) found:\n")
        for error in all_errors:
            print(f"  ERROR: {error}")
        return 1

    print("All cases valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
