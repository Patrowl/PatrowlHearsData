#!/usr/bin/env -S python3 -OO
# coding:utf8

# Copyright (c) 2020-2026, Patrowl and contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.  Redistributions in binary
# form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with
# the distribution
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Pre-computes the CWE -> CAPEC -> MITRE ATT&CK (Enterprise) chain.
#
# CAPEC attack patterns carry both links as external references: "cwe" (CWE IDs)
# and "ATTACK" (technique IDs). Technique names, tactics and URLs are resolved
# from the ATT&CK STIX bundle; techniques revoked in ATT&CK are followed to their
# replacement, since CAPEC lags ATT&CK.
#
# Both inputs are STIX bundles fetched from GitHub (mitre/cti, mitre-attack):
# capec.mitre.org / cwe.mitre.org refuse connections from some networks.
#
# These mappings are INFERRED from the weakness type, not analyst-curated per
# CVE: consumers should label them as such.
#
# Output (data/cwe-attack-mapping.json):
# {
#   "sources": {"capec_version": "3.9", "attack_version": "17.1"},
#   "tactics": {"initial-access": {"id": "TA0001", "name": "Initial Access"}, ...},
#   "mappings": {
#     "CWE-79": [{"technique_id": "T1059.007", "name": "...", "tactics": ["execution"],
#                 "url": "https://attack.mitre.org/techniques/T1059/007", "capec_ids": ["CAPEC-588"]}],
#     ...
#   }
# }
# The output is sorted and carries no timestamp, so it only changes (and gets
# committed) when upstream data changes.

import requests
import os
import json

BASEDIR = os.path.dirname(os.path.realpath(__file__))
CAPEC_STIX_URL = os.environ.get(
    "CAPEC_STIX_URL",
    "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
)
ATTACK_STIX_URL = os.environ.get(
    "ATTACK_STIX_URL",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
)
OUTPUT_FILENAME = os.environ.get("ATTACK_MAPPING_FILENAME", f"{BASEDIR}/data/cwe-attack-mapping.json")
HEADERS = {"User-Agent": "PatrowlHears-Agent"}


def _external_id(stix_obj):
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def parse_attack_stix(bundle: dict):
    """Return (techniques, tactics, version).

    techniques: {"T1190": {"name", "tactics", "url"}} for active techniques, plus
    revoked IDs pointing at their replacement's entry.
    """
    objects = bundle.get("objects", [])
    by_stix_id = {o["id"]: o for o in objects}

    version = ""
    tactics = {}
    for o in objects:
        if o["type"] == "x-mitre-collection":
            version = o.get("x_mitre_version", "")
        elif o["type"] == "x-mitre-tactic" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            tactic_id, _ = _external_id(o)
            tactics[o["x_mitre_shortname"]] = {"id": tactic_id, "name": o["name"]}

    techniques = {}
    for o in objects:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        technique_id, url = _external_id(o)
        if not technique_id:
            continue
        techniques[technique_id] = {
            "name": o["name"],
            "tactics": sorted(
                p["phase_name"] for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ),
            "url": url,
        }

    # Revoked technique -> its replacement (one hop; ATT&CK doesn't chain revocations).
    for o in objects:
        if o["type"] != "relationship" or o.get("relationship_type") != "revoked-by":
            continue
        old, new = by_stix_id.get(o["source_ref"]), by_stix_id.get(o["target_ref"])
        if not old or not new:
            continue
        old_id, _ = _external_id(old)
        new_id, _ = _external_id(new)
        if old_id and new_id in techniques and old_id not in techniques:
            techniques[old_id] = {**techniques[new_id], "replaced_by": new_id}

    return techniques, tactics, version


def parse_capec_stix(bundle: dict):
    """Return (cwe_to_capec_attack, version).

    cwe_to_capec_attack: {"CWE-79": {"CAPEC-588": {"T1059.007", ...}, ...}}
    """
    mapping = {}
    versions = set()
    for ap in bundle.get("objects", []):
        if ap["type"] != "attack-pattern" or ap.get("revoked") \
                or ap.get("x_capec_status") in ("Deprecated", "Obsolete"):
            continue
        versions.add(ap.get("x_capec_version", ""))
        refs = ap.get("external_references", [])
        capec_id = next((r["external_id"] for r in refs if r.get("source_name") == "capec"), None)
        technique_ids = set()
        for r in refs:
            if r.get("source_name") == "ATTACK" and r.get("external_id", "").strip():
                tid = r["external_id"].strip().upper()
                technique_ids.add(tid if tid.startswith("T") else f"T{tid}")
        if not capec_id or not technique_ids:
            continue
        for r in refs:
            if r.get("source_name") == "cwe" and r.get("external_id", "").startswith("CWE-"):
                mapping.setdefault(r["external_id"], {}).setdefault(capec_id, set()).update(technique_ids)
    version = max(versions - {""}, key=lambda v: tuple(int(p) for p in v.split(".")), default="")
    return mapping, version


def build_mapping(capec_bundle: dict, attack_bundle: dict) -> dict:
    techniques, tactics, attack_version = parse_attack_stix(attack_bundle)
    cwe_to_capec, capec_version = parse_capec_stix(capec_bundle)

    unresolved = set()
    mappings = {}
    for cwe_id, capecs in cwe_to_capec.items():
        by_technique = {}
        for capec_id, technique_ids in capecs.items():
            for tid in technique_ids:
                tech = techniques.get(tid)
                if tech is None:
                    unresolved.add(tid)  # e.g. non-Enterprise or removed technique
                    continue
                final_id = tech.get("replaced_by", tid)
                entry = by_technique.setdefault(final_id, {
                    "technique_id": final_id,
                    "name": tech["name"],
                    "tactics": tech["tactics"],
                    "url": tech["url"],
                    "capec_ids": set(),
                })
                entry["capec_ids"].add(capec_id)
        if by_technique:
            mappings[cwe_id] = [
                {**e, "capec_ids": sorted(e["capec_ids"], key=lambda c: int(c.split("-")[1]))}
                for e in sorted(by_technique.values(), key=lambda e: e["technique_id"])
            ]

    if unresolved:
        print(f"[!] {len(unresolved)} CAPEC technique IDs not found in ATT&CK Enterprise: {', '.join(sorted(unresolved))}")

    return {
        "sources": {"capec_version": capec_version, "attack_version": attack_version},
        "tactics": dict(sorted(tactics.items())),
        "mappings": dict(sorted(mappings.items(), key=lambda kv: int(kv[0].split("-")[1]))),
    }


def main():
    print("[+] Downloading latest CAPEC STIX bundle")
    r = requests.get(CAPEC_STIX_URL, headers=HEADERS, timeout=(10, 120))
    r.raise_for_status()
    capec_bundle = r.json()

    print("[+] Downloading latest MITRE ATT&CK Enterprise STIX bundle")
    r = requests.get(ATTACK_STIX_URL, headers=HEADERS, timeout=(10, 300))
    r.raise_for_status()
    attack_bundle = r.json()

    print("[+] Building CWE -> CAPEC -> ATT&CK mapping")
    result = build_mapping(capec_bundle, attack_bundle)

    os.makedirs(os.path.dirname(OUTPUT_FILENAME), exist_ok=True)
    with open(OUTPUT_FILENAME, "w") as f:
        json.dump(result, f, indent=1)
        f.write("\n")

    n_links = sum(len(v) for v in result["mappings"].values())
    print(f"[+] {len(result['mappings'])} CWEs mapped to ATT&CK ({n_links} CWE/technique links) "
          f"- CAPEC {result['sources']['capec_version']}, ATT&CK {result['sources']['attack_version']}")


if __name__ == "__main__":
    main()
