#!/usr/bin/env python3
import json
import glob
from pathlib import Path

# Règles Semgrep intentionnelles dans Juice Shop
FP_RULES = {
    "javascript.browser.security.eval-detected.eval-detected",
    "javascript.lang.security.audit.unsafe-innerhtml.unsafe-innerhtml",
}

# CVE intentionnelles (challenges Juice Shop)
FP_INTENTIONAL_CVES = {
    "CVE-2015-9235",   # jsonwebtoken
    "CVE-2019-10744",  # lodash
}

# CVE sans correctif disponible
FP_NOFIX_CVES = {
    "CVE-2026-53486",   # decompress
    "GHSA-5mrr-rgp6-x4gr",  # marsdb
}

IGNORED_PATHS = [
    "test/",
    "spec/",
    "node_modules/",
    "frontend/node_modules/",
    "dist/",
    "build/",
]

def extract_ids(result):
    ids = set()
    rule = result.get("ruleId")
    if rule:
        ids.add(rule)

    props = result.get("properties", {})
    for key in [
        "vulnerabilityid",
        "primaryVulnerabilityId",
        "security-severity",
        "cvssV3Severity",
    ]:
        value = props.get(key)
        if isinstance(value, str):
            ids.add(value)
        elif isinstance(value, list):
            ids.update(str(v) for v in value)

    return ids

def is_fp(result):
    ids = extract_ids(result)

    # Règles Semgrep
    if ids & FP_RULES:
        return True, "Règle Semgrep intentionnelle"

    # CVE intentionnelles
    if ids & FP_INTENTIONAL_CVES:
        return True, "CVE intentionnelle Juice Shop"

    # CVE sans fix
    if ids & FP_NOFIX_CVES:
        return True, "CVE sans correctif disponible"

    # Chemins ignorés
    for loc in result.get("locations", []):
        uri = (
            loc.get("physicalLocation", {})
               .get("artifactLocation", {})
               .get("uri", "")
        )
        if any(uri.startswith(p) for p in IGNORED_PATHS):
            return True, f"Chemin ignoré: {uri}"

    return False, ""

print("\n===== FALSE POSITIVE FILTER =====")

total_before = 0
total_removed = 0

for file in glob.glob("reports/*.sarif"):
    with open(file) as f:
        data = json.load(f)

    before = 0
    removed = 0

    for run in data.get("runs", []):
        results = run.get("results", [])
        before += len(results)

        filtered = []
        for r in results:
            fp, _ = is_fp(r)
            if fp:
                removed += 1
            else:
                filtered.append(r)

        run["results"] = filtered

    with open(file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"{Path(file).name}: {before} -> {before - removed} ({removed} FP)")

    total_before += before
    total_removed += removed

print(f"\nTotal avant: {total_before}")
print(f"Total supprimé: {total_removed}")
print(f"Total restant: {total_before - total_removed}")
print("========================================\n")
