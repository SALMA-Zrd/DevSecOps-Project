#!/usr/bin/env python3
"""
Liste les CRITICAL/HIGH restants après filtrage, groupés par CVE,
pour t'aider à décider lesquels ajouter à accepted-risks.json.

Usage: python3 scripts/list_remaining_findings.py
(à lancer juste après filter_false_positives.py, sur les mêmes reports/*.sarif)
"""
import json
import glob
from collections import defaultdict

findings = defaultdict(lambda: {"count": 0, "files": set(), "severity": "", "pkg": "", "msg": ""})

for file in glob.glob("reports/*.sarif"):
    with open(file) as f:
        data = json.load(f)

    for run in data.get("runs", []):
        for r in run.get("results", []):
            sev = r.get("properties", {}).get("resolved_severity", "?")
            if sev not in ("CRITICAL", "HIGH"):
                continue

            rule_id = r.get("ruleId", "NO_RULE")
            msg = r.get("message", {}).get("text", "")[:120]
            loc = r.get("locations", [{}])[0]
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")

            key = rule_id
            findings[key]["count"] += 1
            findings[key]["files"].add(f"{file}:{uri}")
            findings[key]["severity"] = sev
            findings[key]["msg"] = msg

# Trie par sévérité puis par nombre d'occurrences
ordered = sorted(findings.items(), key=lambda x: (x[1]["severity"] != "CRITICAL", -x[1]["count"]))

print(f"\n{'ID':<40} {'SEV':<10} {'COUNT':<7} MESSAGE")
print("-" * 130)
for rule_id, info in ordered:
    print(f"{rule_id:<40} {info['severity']:<10} {info['count']:<7} {info['msg']}")

print(f"\nTotal findings uniques CRITICAL/HIGH : {len(ordered)}")
print("\nPour accepter une CVE, ajoute-la dans accepted-risks.json > accepted_cves")
print("avec une vraie raison (pas juste 'pour que ça passe').")
