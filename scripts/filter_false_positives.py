#!/usr/bin/env python3
"""
Filtre les faux positifs dans les rapports SARIF.

Catégories de FP pour Juice Shop :
  1. Règles Semgrep → code intentionnellement vulnérable
  2. CVE intentionnelles → packages volontairement vieux
  3. CVE sans fix → pas de version corrigée disponible
  4. Chemins ignorés → dossiers test, node_modules...
"""

import json
import sys
import glob

# ─────────────────────────────────────────────
# CATÉGORIE 1 — Règles Semgrep FP
# ─────────────────────────────────────────────
FALSE_POSITIVE_RULES = {
    "javascript.browser.security.eval-detected.eval-detected":
        "eval() utilisé intentionnellement dans challenges CTF Juice Shop",

    "javascript.lang.security.audit.unsafe-innerhtml.unsafe-innerhtml":
        "Angular gère la sanitisation via DomSanitizer — pas un vrai FP",
}

# ─────────────────────────────────────────────
# CATÉGORIE 2 — CVE intentionnelles Juice Shop
# Packages volontairement en vieille version
# pour les challenges de sécurité
# ─────────────────────────────────────────────
FP_CVE_INTENTIONAL = {
    "CVE-2015-9235":
        "jsonwebtoken vieille version intentionnelle — challenge Auth Juice Shop",

    "CVE-2019-10744":
        "lodash vieille version intentionnelle — challenge Prototype Pollution",
}

# ─────────────────────────────────────────────
# CATÉGORIE 3 — CVE sans fix disponible
# On ne peut pas corriger → surveiller seulement
# ─────────────────────────────────────────────
FP_CVE_NO_FIX = {
    "CVE-2026-53486":
        "decompress — pas de version corrigée disponible (upstream)",

    "GHSA-5mrr-rgp6-x4gr":
        "marsdb — pas de version corrigée, base NoSQL intentionnellement vulnérable",
}

# ─────────────────────────────────────────────
# CATÉGORIE 4 — Chemins à ignorer
# ─────────────────────────────────────────────
FALSE_POSITIVE_PATHS = [
    "test/",
    "spec/",
    "node_modules/",
    "frontend/node_modules/",
    "build/",
    "dist/",
    "vagrant/",
    "screenshots/",
]


def is_fp(result):
    """
    Analyse une alerte SARIF et détermine si c'est un FP.
    Retourne (bool, str) : (est_fp, raison)
    """
    rule_id = result.get("ruleId", "")

    # Vérif 1 — Règle Semgrep connue comme FP
    if rule_id in FALSE_POSITIVE_RULES:
        return True, f"[Règle FP] {FALSE_POSITIVE_RULES[rule_id]}"

    # Vérif 2 — CVE intentionnelle Juice Shop
    if rule_id in FP_CVE_INTENTIONAL:
        return True, f"[CVE Intentionnelle] {FP_CVE_INTENTIONAL[rule_id]}"

    # Vérif 3 — CVE sans fix disponible
    if rule_id in FP_CVE_NO_FIX:
        return True, f"[CVE No Fix] {FP_CVE_NO_FIX[rule_id]}"

    # Vérif 4 — Fichier dans un chemin ignoré
    for loc in result.get("locations", []):
        uri = (loc.get("physicalLocation", {})
                  .get("artifactLocation", {})
                  .get("uri", ""))
        for path in FALSE_POSITIVE_PATHS:
            if uri.startswith(path):
                return True, f"[Chemin ignoré] {path} → {uri}"

    return False, ""


def main():
    print("=" * 55)
    print("FILTRAGE DES FAUX POSITIFS")
    print("=" * 55)

    sarif_files = glob.glob("reports/*.sarif")

    if not sarif_files:
        print("Aucun fichier SARIF trouvé dans reports/")
        return

    total_avant  = 0
    total_filtre = 0
    total_garde  = 0

    for f in sorted(sarif_files):
        try:
            with open(f) as fp:
                data = json.load(fp)

            avant   = 0
            filtre  = 0
            details = []

            for run in data.get("runs", []):
                original = run.get("results", [])
                avant += len(original)
                filtered = []

                for r in original:
                    est_fp, raison = is_fp(r)
                    if est_fp:
                        filtre += 1
                        details.append({
                            "rule": r.get("ruleId", "?"),
                            "raison": raison
                        })
                    else:
                        filtered.append(r)

                run["results"] = filtered

            # Réécrire le SARIF filtré
            with open(f, 'w') as fp:
                json.dump(data, fp, indent=2)

            garde = avant - filtre
            print(f"\n{f}")
            print(f"  Avant    : {avant} alertes")
            print(f"  Filtrées : {filtre} FP supprimés")
            print(f"  Gardées  : {garde} alertes réelles")

            if details:
                print(f"  Détail FP :")
                for d in details[:5]:
                    print(f"    → [{d['rule']}]")
                    print(f"       {d['raison']}")
                if len(details) > 5:
                    print(f"    ... et {len(details)-5} autres")

            total_avant  += avant
            total_filtre += filtre
            total_garde  += garde

        except Exception as e:
            print(f"\nERREUR sur {f}: {e}")

    print("\n" + "=" * 55)
    print("RÉSUMÉ GLOBAL")
    print("=" * 55)
    print(f"Total avant filtrage  : {total_avant}")
    print(f"Total FP supprimés    : {total_filtre}")
    print(f"Total alertes réelles : {total_garde}")
    if total_avant > 0:
        pct = round(total_filtre / total_avant * 100)
        print(f"Taux de filtrage      : {pct}%")
    print("=" * 55)
    print("✅ Filtrage terminé — SARIF prêts pour Quality Gate")
    print("=" * 55)


if __name__ == "__main__":
    main()
