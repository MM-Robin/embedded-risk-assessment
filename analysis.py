# analysis.py
# Control mapping and risk analysis functions
# Author: Mainuddin Monsur Robin

from collections import Counter
from models import Risk, Control, ControlStatus, ControlType


def get_all_controls(risks: list[Risk]) -> list[Control]:
    """Flatten all controls from all risks into a single list."""
    return [c for r in risks for c in r.controls]


def control_status_summary(risks: list[Risk]) -> dict:
    """Count controls by status across all risks."""
    all_controls = get_all_controls(risks)
    counts = Counter(c.status for c in all_controls)

    total = len(all_controls)
    return {
        "total":           total,
        "implemented":     counts.get(ControlStatus.IMPLEMENTED,     0),
        "partial":         counts.get(ControlStatus.PARTIAL,         0),
        "not_implemented": counts.get(ControlStatus.NOT_IMPLEMENTED, 0),
        "not_applicable":  counts.get(ControlStatus.NOT_APPLICABLE,  0),
        "coverage_pct":    round(
            counts.get(ControlStatus.IMPLEMENTED, 0) / total * 100, 1
        ) if total > 0 else 0,
    }


def controls_by_type(risks: list[Risk]) -> dict:
    """Group controls by type (preventive / detective / corrective)."""
    all_controls = get_all_controls(risks)
    groups = {t: [] for t in ControlType}
    for c in all_controls:
        groups[c.type].append(c)
    return groups


def controls_by_owner(risks: list[Risk]) -> list[tuple]:
    """Count unresolved controls per owner, sorted by most gaps first."""
    all_controls = get_all_controls(risks)
    unresolved = [
        c for c in all_controls
        if c.status == ControlStatus.NOT_IMPLEMENTED
        or c.status == ControlStatus.PARTIAL
    ]
    counts = Counter(c.owner for c in unresolved)
    return counts.most_common()


def risk_exposure_score(risk: Risk) -> float:
    """
    Calculate a risk's exposure score based on CVSS score
    and how many of its controls are unresolved.

    exposure = cvss_score * (unresolved_controls / total_controls)

    A risk scoring 9.6 with no controls implemented = max exposure.
    A risk scoring 9.6 with all controls implemented = zero exposure.
    """
    if not risk.controls:
        return risk.cvss.base_score()

    unresolved = sum(
        1 for c in risk.controls
        if c.status in (ControlStatus.NOT_IMPLEMENTED, ControlStatus.PARTIAL)
    )
    ratio = unresolved / len(risk.controls)
    return round(risk.cvss.base_score() * ratio, 2)


def most_exposed_risks(risks: list[Risk]) -> list[tuple]:
    """Return risks sorted by exposure score, highest first."""
    scored = [(r, risk_exposure_score(r)) for r in risks]
    return sorted(scored, key=lambda x: x[1], reverse=True)


def unimplemented_by_nis2_article(risks: list[Risk]) -> dict:
    """
    Find all unimplemented controls grouped by NIS2 article.
    Shows which regulatory requirements have the most gaps.
    """
    all_controls = get_all_controls(risks)
    gaps = {}
    for c in all_controls:
        if c.status == ControlStatus.NOT_IMPLEMENTED and c.nis2_article:
            if c.nis2_article not in gaps:
                gaps[c.nis2_article] = []
            gaps[c.nis2_article].append(c)
    return dict(sorted(gaps.items()))
