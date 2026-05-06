# report.py
# Terminal report generator — wires all modules together
# Author: Mainuddin Monsur Robin

from colorama import init, Fore, Style
from tabulate import tabulate
from models import ControlStatus, ControlType
from analysis import (
    control_status_summary, controls_by_owner,
    controls_by_type, most_exposed_risks
)
from nis2 import run_gap_analysis, gap_summary, remediation_priorities

init(autoreset=True)

# ── Colour helpers ──────────────────────────────────────────────────────

def severity_colour(severity: str) -> str:
    return {
        "Critical": Fore.RED + Style.BRIGHT,
        "High":     Fore.RED,
        "Medium":   Fore.YELLOW,
        "Low":      Fore.GREEN,
        "None":     Fore.WHITE,
    }.get(severity, "")


def score_bar(score: float, width: int = 20) -> str:
    """Visual bar showing score out of 10."""
    filled = int((score / 10) * width)
    colour = severity_colour(
        "Critical" if score >= 9 else
        "High"     if score >= 7 else
        "Medium"   if score >= 4 else "Low"
    )
    bar = "█" * filled + "░" * (width - filled)
    return f"{colour}[{bar}]{Style.RESET_ALL} {score:.1f}"


def divider(char="─", width=72, colour=Fore.CYAN):
    print(colour + char * width + Style.RESET_ALL)


def section_header(title: str):
    print()
    divider("═", 72)
    print(Fore.CYAN + Style.BRIGHT + f"  {title}" + Style.RESET_ALL)
    divider("═", 72)


def sub_header(title: str):
    print()
    print(Fore.YELLOW + Style.BRIGHT + f"  ▶  {title}" + Style.RESET_ALL)
    divider("─", 72, Fore.YELLOW)


# ── Report sections ─────────────────────────────────────────────────────

def print_banner():
    print()
    print(Fore.CYAN + Style.BRIGHT + "=" * 72)
    print("  EMBEDDED SYSTEM CYBERSECURITY RISK ASSESSMENT TOOL")
    print("  CVSS v3.1  |  NIS2-Aligned  |  ARM Cortex-M4 IoT Gateway")
    print("  Author: Mainuddin Monsur Robin  |  HAW Hamburg")
    print("=" * 72 + Style.RESET_ALL)


def print_risk_register(risks):
    section_header("RISK REGISTER  —  CVSS v3.1 BASE SCORES")

    rows = []
    for r in sorted(risks, key=lambda x: x.cvss.base_score(), reverse=True):
        score    = r.cvss.base_score()
        severity = r.cvss.severity()
        col      = severity_colour(severity)
        nis2_tag = "🔴 NIS2" if r.nis2_relevant else ""
        rows.append([
            r.id,
            r.threat,
            score_bar(score),
            col + severity + Style.RESET_ALL,
            nis2_tag,
        ])

    print(tabulate(rows,
        headers=["ID", "Threat", "Score", "Severity", "Regulatory"],
        tablefmt="rounded_outline"))


def print_risk_details(risks):
    section_header("DETAILED RISK ANALYSIS")

    for r in sorted(risks, key=lambda x: x.cvss.base_score(), reverse=True):
        score    = r.cvss.base_score()
        severity = r.cvss.severity()
        col      = severity_colour(severity)

        sub_header(
            f"[{r.id}] {r.threat}  —  "
            f"{col}{severity} ({score:.1f}){Style.RESET_ALL}"
        )

        print(f"  {Fore.WHITE}Component  :{Style.RESET_ALL} {r.component}")
        print(f"  {Fore.WHITE}Description:{Style.RESET_ALL} {r.description}")
        if r.nis2_relevant:
            print(f"  {Fore.RED}NIS2 relevant — requires regulatory attention{Style.RESET_ALL}")

        # Controls table
        if r.controls:
            print()
            ctrl_rows = []
            for c in r.controls:
                status_col = {
                    ControlStatus.IMPLEMENTED:     Fore.GREEN,
                    ControlStatus.PARTIAL:         Fore.YELLOW,
                    ControlStatus.NOT_IMPLEMENTED: Fore.RED,
                    ControlStatus.NOT_APPLICABLE:  Fore.WHITE,
                }.get(c.status, "")
                ctrl_rows.append([
                    c.id,
                    c.name,
                    c.type.value,
                    status_col + c.status.value + Style.RESET_ALL,
                    c.owner,
                    c.nis2_article or "—",
                ])
            print(tabulate(ctrl_rows,
                headers=["ID", "Control", "Type", "Status", "Owner", "NIS2"],
                tablefmt="simple"))

        print(f"\n  {Fore.GREEN}Remediation:{Style.RESET_ALL} {r.remediation}")
        print()
        divider("·", 72, Fore.WHITE)


def print_control_summary(risks):
    section_header("CONTROL EFFECTIVENESS SUMMARY")

    # Status breakdown
    summary = control_status_summary(risks)
    print(f"\n  Total controls   : {summary['total']}")
    print(f"  {Fore.GREEN}Implemented      : {summary['implemented']}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Partial          : {summary['partial']}{Style.RESET_ALL}")
    print(f"  {Fore.RED}Not implemented  : {summary['not_implemented']}{Style.RESET_ALL}")
    print(f"  Coverage         : {summary['coverage_pct']}%")

    # By type
    sub_header("Controls by Type")
    type_rows = []
    for ctype, ctrls in controls_by_type(risks).items():
        implemented = sum(1 for c in ctrls if c.status == ControlStatus.IMPLEMENTED)
        partial     = sum(1 for c in ctrls if c.status == ControlStatus.PARTIAL)
        missing     = sum(1 for c in ctrls if c.status == ControlStatus.NOT_IMPLEMENTED)
        type_rows.append([ctype.value, len(ctrls), implemented, partial, missing])
    print(tabulate(type_rows,
        headers=["Type", "Total", "Implemented", "Partial", "Not Implemented"],
        tablefmt="simple"))

    # By owner
    sub_header("Unresolved Controls by Owner")
    owner_rows = [[owner, count] for owner, count in controls_by_owner(risks)]
    print(tabulate(owner_rows,
        headers=["Owner", "Unresolved"],
        tablefmt="simple"))

    # Exposure ranking
    sub_header("Risk Exposure Ranking")
    exp_rows = []
    for risk, exposure in most_exposed_risks(risks):
        exp_rows.append([
            risk.id,
            risk.threat,
            risk.cvss.base_score(),
            exposure,
        ])
    print(tabulate(exp_rows,
        headers=["ID", "Threat", "CVSS", "Exposure"],
        tablefmt="simple",
        floatfmt=".1f"))


def print_nis2_report(risks):
    section_header("NIS2 ARTICLE 21 GAP ANALYSIS")

    print(f"  {Fore.WHITE}Directive: NIS2 (EU) 2022/2555 — Network and Information Security{Style.RESET_ALL}")

    results = run_gap_analysis(risks)
    summary = gap_summary(results)

    print()
    rows = []
    for article, data in remediation_priorities(results):
        status_col = {
            "COVERED": Fore.GREEN + "✅ Covered",
            "PARTIAL": Fore.YELLOW + "⚠️  Partial",
            "GAP":     Fore.RED    + "❌ Gap",
        }[data["status"]]
        rows.append([
            article,
            data["description"],
            status_col + Style.RESET_ALL,
        ])

    print(tabulate(rows,
        headers=["Article", "Requirement", "Status"],
        tablefmt="rounded_outline"))

    print()
    print(f"  {Fore.GREEN}✅ Covered : {summary['COVERED']}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}⚠️  Partial : {summary['PARTIAL']}{Style.RESET_ALL}")
    print(f"  {Fore.RED}❌ Gap     : {summary['GAP']}{Style.RESET_ALL}")

    total = sum(summary.values())
    pct   = round(summary["COVERED"] / total * 100)
    print(f"\n  Compliance coverage: {pct}% ({summary['COVERED']}/{total} articles)")


def print_executive_summary(risks):
    section_header("EXECUTIVE SUMMARY")

    scores   = [r.cvss.base_score() for r in risks]
    avg      = round(sum(scores) / len(scores), 1)
    critical = sum(1 for r in risks if r.cvss.severity() == "Critical")
    high     = sum(1 for r in risks if r.cvss.severity() == "High")
    medium   = sum(1 for r in risks if r.cvss.severity() == "Medium")
    nis2_ct  = sum(1 for r in risks if r.nis2_relevant)
    top      = max(risks, key=lambda r: r.cvss.base_score())

    print(f"""
  System        : ARM Cortex-M4 IoT Gateway — FreeRTOS 10.4
  Assessment    : CVSS v3.1 Base Score | NIS2 Article 21

  ┌─────────────────────────────────────┐
  │  Risk distribution                  │
  │                                     │
  │  {Fore.RED + Style.BRIGHT}Critical : {critical:<2}{Style.RESET_ALL}                         │
  │  {Fore.RED}High     : {high:<2}{Style.RESET_ALL}                         │
  │  {Fore.YELLOW}Medium   : {medium:<2}{Style.RESET_ALL}                         │
  │                                     │
  │  Avg CVSS score  : {avg} / 10.0        │
  │  NIS2-relevant   : {nis2_ct} risks           │
  └─────────────────────────────────────┘

  {Fore.RED}Highest priority risk:{Style.RESET_ALL}
  [{top.id}] {top.threat}
  Score: {top.cvss.base_score()}  |  {top.cvss.severity()}
  → {top.remediation}
""")


# ── Main ────────────────────────────────────────────────────────────────

def generate_report(risks):
    print_banner()
    print_executive_summary(risks)
    print_risk_register(risks)
    print_risk_details(risks)
    print_control_summary(risks)
    print_nis2_report(risks)

    section_header("ASSESSMENT COMPLETE")
    print(f"  {Fore.GREEN}✅ {len(risks)} risks assessed.{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}⚠️  Review all Not Implemented controls before deployment.{Style.RESET_ALL}")
    print(f"  {Fore.RED}🔴 NIS2-relevant risks require immediate regulatory attention.{Style.RESET_ALL}")
    print()


if __name__ == "__main__":
    from risks import build_risk_register
    risks = build_risk_register()
    generate_report(risks)