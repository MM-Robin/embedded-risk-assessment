# nis2.py
# NIS2 Article 21 gap analysis engine
# Author: Mainuddin Monsur Robin

from models import Risk, Control, ControlStatus
from analysis import get_all_controls


# All Article 21(2) requirements we check
NIS2_ARTICLES = {
    "Art. 21(2)(a)": "Risk analysis and information security policies",
    "Art. 21(2)(b)": "Incident handling and response procedures",
    "Art. 21(2)(c)": "Business continuity and crisis management",
    "Art. 21(2)(e)": "Supply chain security",
    "Art. 21(2)(g)": "Vulnerability handling and disclosure",
    "Art. 21(2)(h)": "Cryptography and encryption",
    "Art. 21(2)(i)": "Human resources security and access control",
    "Art. 21(2)(j)": "MFA and secure communications",
}


def check_article(article: str, controls: list[Control]) -> str:
    """
    Check compliance status for a single NIS2 article.

    Returns one of:
      "COVERED"  — at least one fully implemented control
      "PARTIAL"  — controls exist but none fully implemented
      "GAP"      — no controls reference this article at all
    """
    # Find all controls linked to this article
    linked = [c for c in controls if c.nis2_article == article]

    if not linked:
        return "GAP"

    # Check if any are fully implemented
    if any(c.status == ControlStatus.IMPLEMENTED for c in linked):
        return "COVERED"

    # Controls exist but none fully implemented
    return "PARTIAL"


def run_gap_analysis(risks: list[Risk]) -> dict:
    """
    Run full NIS2 gap analysis across all risks.
    Returns a dict of article -> result details.
    """
    all_controls = get_all_controls(risks)
    results = {}

    for article, description in NIS2_ARTICLES.items():
        status = check_article(article, all_controls)

        # Find linked controls for reporting
        linked = [c for c in all_controls if c.nis2_article == article]

        results[article] = {
            "description":    description,
            "status":         status,
            "linked_controls": linked,
            "gap_count":      sum(
                1 for c in linked
                if c.status == ControlStatus.NOT_IMPLEMENTED
            ),
        }

    return results


def gap_summary(results: dict) -> dict:
    """Count articles by status."""
    counts = {"COVERED": 0, "PARTIAL": 0, "GAP": 0}
    for r in results.values():
        counts[r["status"]] += 1
    return counts


def remediation_priorities(results: dict) -> list[tuple]:
    """
    Return articles sorted by urgency.
    GAP first, then PARTIAL, then COVERED.
    Within each group, sorted by number of unimplemented controls.
    """
    priority_order = {"GAP": 0, "PARTIAL": 1, "COVERED": 2}
    items = list(results.items())
    return sorted(
        items,
        key=lambda x: (priority_order[x[1]["status"]], -x[1]["gap_count"])
    )