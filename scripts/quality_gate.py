#!/usr/bin/env python3
import json
import glob
import os
import sys
from pathlib import Path

THRESHOLD = os.getenv("QUALITY_GATE_THRESHOLD", "HIGH").upper()

critical = 0
high = 0
medium = 0
low = 0

print("\n========================================================")
print("QUALITY GATE")
print("========================================================")

for file in glob.glob("reports/*.sarif"):
    with open(file) as f:
        data = json.load(f)

    c = h = m = l = 0

    for run in data.get("runs", []):
        for result in run.get("results", []):
            level = result.get("level", "").lower()

            if level == "error":
                c += 1
            elif level == "warning":
                h += 1
            elif level == "note":
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
