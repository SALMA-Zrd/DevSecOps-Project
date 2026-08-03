#!/usr/bin/env python3
import json, sys, glob, os

def main():
    print("=== Quality Gate ===")
    sarif_files = glob.glob("reports/*.sarif")
    if not sarif_files:
        print("Aucun SARIF — gate ignorée")
        sys.exit(0)

    total_critical = 0
    total_high = 0

    for f in sarif_files:
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
            print(f"  {f}: CRITICAL={c}, HIGH={h}")
            total_critical += c
            total_high += h
        except Exception as e:
            print(f"  Erreur {f}: {e}")

    print(f"\nTotal → CRITICAL: {total_critical}, HIGH: {total_high}")
    threshold = os.getenv("QUALITY_GATE_THRESHOLD", "CRITICAL")

    if threshold == "CRITICAL" and total_critical > 0:
        print(f"\n❌ BLOQUÉ — {total_critical} faille(s) CRITICAL")
        sys.exit(1)
    elif threshold == "HIGH" and (total_critical + total_high) > 0:
        print(f"\n❌ BLOQUÉ — failles CRITICAL/HIGH détectées")
        sys.exit(1)
    else:
        print("\n✅ Quality Gate : PASSED")
        sys.exit(0)

if __name__ == "__main__":
    main()
