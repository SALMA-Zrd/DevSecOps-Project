#!/usr/bin/env python3
"""
Quality Gate — décide si le pipeline passe ou est bloqué.
S'exécute APRÈS le filtrage des faux positifs.

Seules les vraies failles bloquent le pipeline :
  crypto-js CVE-2023-46233 → CRITICAL → BLOQUE
  tar CVE-2026-59873        → CRITICAL → BLOQUE
"""

import json
import sys
import glob
import os


def main():
    print("=" * 55)
    print("QUALITY GATE")
    print("=" * 55)

    sarif_files = glob.glob("reports/*.sarif")

    if not sarif_files:
        print("Aucun SARIF — Quality Gate ignorée")
        sys.exit(0)

    total_critical = 0
    total_high     = 0

    for f in sorted(sarif_files):
        try:
            with open(f) as fp:
                data = json.load(fp)

            c, h = 0, 0
            for run in data.get("runs", []):
                for r in run.get("results", []):
                    level = r.get("level", "")
                    if level == "error":
                        c += 1
                    elif level == "warning":
                        h += 1

            print(f"  {f}")
            print(f"    CRITICAL : {c}")
            print(f"    HIGH     : {h}")

            total_critical += c
            total_high     += h

        except Exception as e:
            print(f"  ERREUR {f}: {e}")

    print(f"\nTotal → CRITICAL: {total_critical}, HIGH: {total_high}")

    threshold = os.getenv("QUALITY_GATE_THRESHOLD", "CRITICAL")
    print(f"Threshold : {threshold}")

    if threshold == "CRITICAL" and total_critical > 0:
        print(f"\n❌ PIPELINE BLOQUÉ")
        print(f"   {total_critical} faille(s) CRITICAL détectée(s)")
        print(f"   Corriger avant de déployer !")
        sys.exit(1)

    elif threshold == "HIGH" and (total_critical + total_high) > 0:
        print(f"\n❌ PIPELINE BLOQUÉ")
        print(f"   Failles CRITICAL/HIGH détectées")
        sys.exit(1)

    else:
        print(f"\n✅ Quality Gate : PASSED")
        print(f"   Aucune faille {threshold} après filtrage des FP")
        sys.exit(0)


if __name__ == "__main__":
    main()
