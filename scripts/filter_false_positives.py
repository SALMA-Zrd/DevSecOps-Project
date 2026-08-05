#!/usr/bin/env python3
"""
Filtre les faux positifs des rapports SARIF avant la Quality Gate.

Corrections apportées vs la v1 :
  1. La sévérité réelle de Trivy n'est PAS dans "level" (qui ne connaît que
     error/warning/note/none) mais dans properties.tags ou
     properties["security-severity"]. On l'extrait correctement ici et on
     la RÉÉCRIT dans le résultat (clé properties["resolved_severity"]) pour
     que quality_gate.py n'ait plus à deviner.
  2. La liste de CVE codées en dur est gardée en dernier recours, mais le
     gros du filtrage "pas de correctif" doit se faire en amont avec
     `ignore-unfixed: true` + `.trivyignore` dans le pipeline (voir README).
  3. Config externalisée dans accepted-risks.json pour ne pas avoir à
     toucher au code Python à chaque nouvelle CVE acceptée.
"""
import json
import glob
import os
from pathlib import Path

CONFIG_PATH = os.getenv("ACCEPTED_RISKS_FILE", "accepted-risks.json")

DEFAULT_CONFIG = {
    "fp_semgrep_rules": [
        "javascript.browser.security.eval-detected.eval-detected",
        "javascript.lang.security.audit.unsafe-innerhtml.unsafe-innerhtml",
    ],
    "accepted_cves": [
        {"id": "CVE-2015-9235", "reason": "jsonwebtoken - vuln volontaire Juice Shop"},
        {"id": "CVE-2019-10744", "reason": "lodash - vuln volontaire Juice Shop"},
    ],
    "ignored_path_substrings": [
        "test/", "spec/", "node_modules/",
        "frontend/node_modules/", "dist/", "build/",
    ],
}


def load_config():
    if Path(CONFIG_PATH).exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    print(f"⚠️  {CONFIG_PATH} introuvable, utilisation de la config par défaut intégrée")
    return DEFAULT_CONFIG


def get_trivy_severity(result):
    """Extrait la vraie sévérité Trivy depuis properties.tags / security-severity.
    Retourne None si le résultat ne vient pas de Trivy (pas de ces clés)."""
    props = result.get("properties", {})
    tags = props.get("tags", [])
    for t in tags:
        if isinstance(t, str) and t.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return t.upper()

    score = props.get("security-severity")
    if score:
        try:
            s = float(score)
            if s >= 9.0:
                return "CRITICAL"
            if s >= 7.0:
                return "HIGH"
            if s >= 4.0:
                return "MEDIUM"
            return "LOW"
        except (TypeError, ValueError):
            pass
    return None


def resolve_severity(result, filename):
    """Sévérité unifiée, quelle que soit la source (trivy-image/fs/iac ou semgrep)."""
    if "semgrep" in filename.lower():
        level = result.get("level", "note").lower()
        return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "LOW")

    trivy_sev = get_trivy_severity(result)
    if trivy_sev:
        return trivy_sev

    # Dernier recours (ex: trivy-iac sans tags exploitables)
    level = result.get("level", "note").lower()
    return {"error": "CRITICAL", "warning": "HIGH", "note": "MEDIUM"}.get(level, "LOW")


def extract_ids(result):
    ids = set()
    rule = result.get("ruleId")
    if rule:
        ids.add(rule)
    props = result.get("properties", {})
    for key in ("vulnerabilityid", "primaryVulnerabilityId"):
        value = props.get(key)
        if isinstance(value, str):
            ids.add(value)
        elif isinstance(value, list):
            ids.update(str(v) for v in value)
    return ids


def is_fp(result, config):
    ids = extract_ids(result)

    fp_semgrep = set(config.get("fp_semgrep_rules", []))
    if ids & fp_semgrep:
        return True, "Règle Semgrep intentionnelle"

    accepted_ids = {c["id"] for c in config.get("accepted_cves", [])}
    if ids & accepted_ids:
        return True, "CVE acceptée (voir accepted-risks.json)"

    ignored_paths = config.get("ignored_path_substrings", [])
    for loc in result.get("locations", []):
        uri = (
            loc.get("physicalLocation", {})
               .get("artifactLocation", {})
               .get("uri", "")
        )
        # "in" plutôt que "startswith" : plus robuste si le scan-ref
        # ajoute un préfixe (ex: "juice-shop/test/...")
        if any(p in uri for p in ignored_paths):
            return True, f"Chemin ignoré: {uri}"

    return False, ""


def main():
    config = load_config()
    print("\n===== FALSE POSITIVE FILTER =====")

    total_before = 0
    total_removed = 0

    files = glob.glob("reports/*.sarif")
    if not files:
        print("⚠️  Aucun fichier reports/*.sarif trouvé — rien à filtrer.")
        print("    (normal en local si tu n'as pas téléchargé/copié les SARIF)")

    for file in files:
        with open(file) as f:
            data = json.load(f)

        before = 0
        removed = 0
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for run in data.get("runs", []):
            results = run.get("results", [])
            before += len(results)

            filtered = []
            for r in results:
                fp, reason = is_fp(r, config)
                if fp:
                    removed += 1
                    continue
                sev = resolve_severity(r, file)
                r.setdefault("properties", {})["resolved_severity"] = sev
                sev_counts[sev] += 1
                filtered.append(r)

            run["results"] = filtered

        with open(file, "w") as f:
            json.dump(data, f, indent=2)

        print(f"{Path(file).name}: {before} -> {before - removed} ({removed} FP) "
              f"| restant: C={sev_counts['CRITICAL']} H={sev_counts['HIGH']} "
              f"M={sev_counts['MEDIUM']} L={sev_counts['LOW']}")

        total_before += before
        total_removed += removed

    print(f"\nTotal avant: {total_before}")
    print(f"Total supprimé: {total_removed}")
    print(f"Total restant: {total_before - total_removed}")
    print("========================================\n")


if __name__ == "__main__":
    main()
