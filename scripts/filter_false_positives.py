#!/usr/bin/env python3
import json, sys, glob

FALSE_POSITIVE_RULES = {
    "javascript.browser.security.eval-detected.eval-detected":
        "eval() utilisé dans les challenges CTF intentionnels de Juice Shop",
    "javascript.lang.security.audit.unsafe-innerhtml.unsafe-innerhtml":
        "Angular gère la sanitisation via DomSanitizer",
}

FALSE_POSITIVE_PATHS = [
    "test/", "spec/", "node_modules/",
    "frontend/node_modules/", "build/", "dist/"
]

def is_fp(result):
    rule_id = result.get("ruleId", "")
    if rule_id in FALSE_POSITIVE_RULES:
        return True, FALSE_POSITIVE_RULES[rule_id]
    for loc in result.get("locations", []):
        uri = loc.get("physicalLocation", {}).get(
            "artifactLocation", {}).get("uri", "")
        for path in FALSE_POSITIVE_PATHS:
            if uri.startswith(path):
                return True, f"Chemin ignoré: {path}"
    return False, ""

def main():
    print("=== Filtrage des faux positifs ===")
    sarif_files = glob.glob("reports/*.sarif")
    if not sarif_files:
        print("Aucun SARIF trouvé")
        return
    total_fp = 0
    for f in sarif_files:
        try:
            with open(f) as fp:
                data = json.load(fp)
            fp_count = 0
            for run in data.get("runs", []):
                original = run.get("results", [])
                filtered = []
                for r in original:
                    is_false, reason = is_fp(r)
                    if is_false:
                        fp_count += 1
                    else:
                        filtered.append(r)
                run["results"] = filtered
            with open(f, 'w') as fp:
                json.dump(data, fp, indent=2)
            print(f"  {f}: {fp_count} FP supprimés")
            total_fp += fp_count
        except Exception as e:
            print(f"  Erreur {f}: {e}")
    print(f"Total FP filtrés: {total_fp}")
    print("✅ Filtrage terminé")

if __name__ == "__main__":
    main()
