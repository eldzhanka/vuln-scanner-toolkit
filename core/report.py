"""
Shared results reporting used by every scanner module.

Each module reports findings through this class instead of printing
directly, so output stays consistent and can optionally be exported
to JSON/text regardless of which module produced it.
"""

import json
from datetime import datetime, timezone


class Report:
    def __init__(self, module_name):
        self.module_name = module_name
        self.findings = []
        self.started_at = datetime.now(timezone.utc).isoformat()

    def add_finding(self, **details):
        """Record a finding. Accepts arbitrary keyword fields per module
        (e.g. payload=..., url=..., marker=... for path traversal;
        token=..., issue=... for JWT)."""
        self.findings.append(details)
        self._print_finding(details)

    def _print_finding(self, details):
        print("[+] Finding recorded!")
        for key, value in details.items():
            print(f"    {key}: {value}")
        print()

    def summarize(self):
        if not self.findings:
            print(f"[-] No issues detected by the {self.module_name} module.")
        else:
            print(f"[*] {len(self.findings)} finding(s) recorded by the {self.module_name} module.")

    def save(self, output_path):
        payload = {
            "module": self.module_name,
            "started_at": self.started_at,
            "finding_count": len(self.findings),
            "findings": self.findings,
        }
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            print(f"[*] Results saved to {output_path}")
        except OSError as e:
            print(f"[-] Could not save results to '{output_path}': {e}")
