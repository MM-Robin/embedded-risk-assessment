# main.py
# Entry point for the Embedded System Cybersecurity Risk Assessment Tool
# Run with: python3 main.py
# Author: Mainuddin Monsur Robin

from risks import build_risk_register
from report import generate_report


def main():
    risks = build_risk_register()
    generate_report(risks)


if __name__ == "__main__":
    main()