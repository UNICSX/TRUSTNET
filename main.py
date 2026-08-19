import json

from coordinator import Coordinator

from phishing_agent import PhishingAgent
from threat_hunter.threat_agent import ThreatHunterAgent
from soc.soc_agent import SOCAgent


def main():

    phishing = PhishingAgent()

    threat = ThreatHunterAgent()

    soc = SOCAgent()

    coordinator = Coordinator(
        phishing_agent=phishing,
        threat_agent=threat,
        soc_agent=soc,
    )

    task = input(
        "\nEnter investigation request:\n> "
    )

    report = coordinator.investigate(task)

    print("\n")
    print("=" * 80)
    print("FINAL EXECUTIVE REPORT")
    print("=" * 80)
    print(json.dumps(report, indent=4, default=str))

    with open(
        "final_report.json",
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            report,
            f,
            indent=4,
            ensure_ascii=False,
            default=str,
        )

    print("\nReport saved to final_report.json")


if __name__ == "__main__":
    main()