#!/usr/bin/env python3
"""Справочник ATT&CK Enterprise для формы закрытия: компактный JSON из STIX MITRE.

    python3 -I scripts/attack-enterprise.py enterprise-attack-20.0.json 20.0 <url>

STIX: https://github.com/mitre-attack/attack-stix-data (enterprise-attack/*.json).
Пишет одинаковые файлы в engine/internal/attack/enterprise.json (go:embed, проверка
метки) и web/src/lib/shared/attack-enterprise.json (кандидаты формы). Тактики — в
порядке матрицы, техники и подтехники без revoked и deprecated, по возрастанию ID.
"""
import hashlib
import json
import pathlib
import sys

src, version, url = sys.argv[1], sys.argv[2], sys.argv[3]
raw = pathlib.Path(src).read_bytes()
objs = json.loads(raw)["objects"]


def live(o):
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def ext_id(o):
    return next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")


matrix = next(o for o in objs if o["type"] == "x-mitre-matrix" and live(o))
by_id = {o["id"]: o for o in objs}
tactics = [by_id[ref] for ref in matrix["tactic_refs"]]
short = [t["x_mitre_shortname"] for t in tactics]
techniques = []
for o in objs:
    if o["type"] != "attack-pattern" or not live(o):
        continue
    phases = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"]
    phases = [s for s in short if s in phases]
    if phases:
        techniques.append({"id": ext_id(o), "name": o["name"], "tactics": phases})
techniques.sort(key=lambda t: [int(x) for x in t["id"][1:].split(".")])
modified = max(o.get("modified", "") for o in objs if o["type"] in ("attack-pattern", "x-mitre-tactic", "x-mitre-matrix"))
doc = {
    "source": "MITRE ATT&CK Enterprise (attack-stix-data)",
    "version": version,
    "url": url,
    "sha256": hashlib.sha256(raw).hexdigest(),
    "modified": modified,
    "tactics": [{"id": ext_id(t), "shortname": t["x_mitre_shortname"], "name": t["name"]} for t in tactics],
    "techniques": techniques,
}
text = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
root = pathlib.Path(__file__).resolve().parent.parent
for out in ("engine/internal/attack/enterprise.json", "web/src/lib/shared/attack-enterprise.json"):
    (root / out).write_text(text, encoding="utf-8")
print(f"ATT&CK {version}: {len(doc['tactics'])} тактик, {len(techniques)} техник")
