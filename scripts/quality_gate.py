#!/usr/bin/env python3
"""
Quality Gate — corrige le bug de mapping level -> sévérité.

AVANT (bug) : level "error" était compté comme CRITICAL, "warning" comme HIGH.
Or Trivy mappe CRITICAL *et* HIGH tous les deux sur "error" dans le SARIF.
Résultat : le décompte CRITICAL/HIGH était faux dès le départ, avant même
le filtrage des FP.

APRÈS : on relit properties["resolved_severity"] écrit par
filter_false_positives.py (qui, lui, lit properties.tags /
properties["security-severity"] — la vraie sévérité de Trivy).
Si le champ est absent (fichier non filtré au préalable), on retombe sur
un mapping level par défaut en dernier recours, avec un avertissement.
"""
import json
import glob
import os
import sys
from pathlib import Path

THRESHOLD = os.getenv("QUALITY_GATE_THRESHOLD", "HIGH").upper()

FALLBACK_LEVEL_MAP = {
    "error": "CRITICAL",
    "warning": "HIGH",
    "note": "MEDIUM",
}


def get_severity(result, filename, warned):
    props = result.get("properties", {})
    sev = props.get("resolved_severity")
    if sev:
        return sev

    if not warned.get(filename):
        print(f"⚠️  {filename}: pas de resolved_severity — "
              f"as-tu bien lancé filter_false_positives.py avant ? "
              f"(fallback sur level, imprécis pour Trivy)")
        warned[filename] = True

    level = result.get("level", "note").lower()
    return FALLBACK_LEVEL_MAP.get(level, "LOW")


def main():
    critical = high = medium = low = 0
    warned = {}

    print("\n========================================================")
    print("QUALITY GATE")
    print("========================================================")

    files = glob.glob("reports/*.sarif")
    if not files:
        print("⚠️  Aucun fichier reports/*.sarif trouvé.")

    for file in files:
        with open(file) as f:
            data = json.load(f)

        c = h = m = l = 0
        for run in data.get("runs", []):
            for result in run.get("results", []):
                sev = get_severity(result, file, warned)
                if sev == "CRITICAL":
                    c += 1
                elif sev == "HIGH":
                    h += 1
                elif sev == "MEDIUM":
                    m += 1
                else:
                    l += 1

        print(f"\n{Path(file).name}")
        print(f"  CRITICAL : {c}")
        print(f"  HIGH     : {h}")
        print(f"  MEDIUM   : {m}")
        print(f"  LOW      : {l}")

        critical += c
        high += h
        medium += m
        low += l

    print("\n--------------------------------------------------------")
    print(f"TOTAL CRITICAL : {critical}")
    print(f"TOTAL HIGH     : {high}")
    print(f"TOTAL MEDIUM   : {medium}")
    print(f"TOTAL LOW      : {low}")
    print(f"Threshold      : {THRESHOLD}")
    print("--------------------------------------------------------\n")

    failed = False
    if THRESHOLD == "CRITICAL":
        failed = critical > 0
    elif THRESHOLD == "HIGH":
        failed = (critical + high) > 0
    elif THRESHOLD == "MEDIUM":
        failed = (critical + high + medium) > 0

    if failed:
        print("❌ PIPELINE BLOQUÉ")
        print("Des vulnérabilités au-dessus du seuil ont été détectées.")
        sys.exit(1)

    print("✅ QUALITY GATE PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
