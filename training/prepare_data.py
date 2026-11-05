#!/usr/bin/env python3
"""Build description -> name training pairs from public, human-written titles.

Usage: prepare_data.py <cvelist bulk zip> <nuclei cves.json> <kev.json>
                       <advisory-database dir> <output.json>
"""

import collections
import glob
import hashlib
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import vulnamer as V  # noqa: E402

CURATED = {"nuclei", "kev", "ghsa"}
# CNAs whose titles are written as names rather than, say, commit subjects.
GOOD_CNAS = {
    "Wordfence", "WPScan", "Patchstack", "VulnCheck", "microsoft", "adobe", "cisco", "ibm",
    "apache", "icscert", "zdi", "GitHub_M", "redhat",
}  # fmt: skip
WORDPRESS_CNAS = {"Wordfence", "WPScan", "Patchstack"}
MAX_WORDPRESS_PAIRS = 18000
MAX_WEAK_PAIRS = 25000
WEAK_BEFORE_YEAR = 2019


def read_cvelist(path):
    """Return {CVE ID: (description, title, CNA)}, including the assigner of each CVE."""
    import io
    import zipfile

    records = {}
    with zipfile.ZipFile(path) as outer:
        archive = outer
        nested = [name for name in outer.namelist() if name.endswith(".zip")]
        if nested:
            archive = zipfile.ZipFile(io.BytesIO(outer.read(nested[0])))
        for name in archive.namelist():
            if not name.endswith(".json") or "/CVE-" not in name:
                continue
            try:
                record = json.loads(archive.read(name))
                parsed = V.parse_cve_record(record)
            except ValueError:
                continue
            if parsed:
                cve_id, description, title = parsed
                assigner = record["cveMetadata"].get("assignerShortName", "")
                records[cve_id] = (description, title, assigner)
    return records


def main():
    cvelist, nuclei_path, kev_path, advisories, output = sys.argv[1:6]
    records = read_cvelist(cvelist)
    with open(nuclei_path, encoding="utf-8") as file:
        nuclei = V.parse_nuclei(file.read())
    with open(kev_path, encoding="utf-8") as file:
        kev = V.parse_kev(file.read())
    ghsa = {}
    pattern = os.path.join(advisories, "advisories/github-reviewed/**/*.json")
    for path in glob.glob(pattern, recursive=True):
        with open(path, encoding="utf-8") as file:
            advisory = json.load(file)
        for alias in advisory.get("aliases", []):
            if alias.startswith("CVE-") and advisory.get("summary"):
                ghsa[alias] = advisory["summary"]

    pairs = {}

    def add(cve_id, source, raw):
        if cve_id not in records or cve_id in pairs:
            return
        description = records[cve_id][0]
        context = "" if source in CURATED else description
        name = V.clean_name(raw, context)
        if not name:
            return
        target = V.strip_versions(name)
        if not V.is_good_name(target, context) or V._tokens(target.lower())[0] in V.VULN_WORDS:
            return
        pairs[cve_id] = (source, target)

    for source, names in (("nuclei", nuclei), ("kev", kev), ("ghsa", ghsa)):
        for cve_id, raw in names.items():
            add(cve_id, source, raw)
    for cve_id, (description, title, assigner) in records.items():
        add(cve_id, "vendor", V.vendor_name(description))
        if assigner in GOOD_CNAS:
            add(cve_id, "cna:" + assigner, title)

    # older descriptions are rarely titled, so label regular ones with the heuristic
    random.seed(5)
    weak = {}
    candidates = [
        c for c in records if c not in pairs and int(c.split("-")[1]) < WEAK_BEFORE_YEAR
    ]
    random.shuffle(candidates)
    for cve_id in candidates:
        name = V.heuristic_name(records[cve_id][0], leading_flaw_only=True)
        if name and V.is_good_name(name, records[cve_id][0]):
            weak[cve_id] = name
        if len(weak) >= MAX_WEAK_PAIRS:
            break

    random.seed(3)
    wordpress = [
        c for c, (source, _) in pairs.items() if source.split(":")[-1] in WORDPRESS_CNAS
    ]
    random.shuffle(wordpress)
    dropped = set(wordpress[MAX_WORDPRESS_PAIRS:])

    rows = []
    for cve_id, (source, target) in pairs.items():
        if cve_id in dropped:
            continue
        # split by product so that evaluation only sees unseen products
        group = " ".join(V._tokens(target.lower())[:2])
        bucket = int(hashlib.sha1(group.encode()).hexdigest(), 16) % 100
        split = "test" if bucket < 5 else "val" if bucket < 8 else "train"
        rows.append({"cve": cve_id, "src": source, "target": target,
                     "text": records[cve_id][0], "split": split})  # fmt: skip
    for cve_id, target in weak.items():
        rows.append({"cve": cve_id, "src": "weak", "target": target,
                     "text": records[cve_id][0], "split": "train"})  # fmt: skip

    print(collections.Counter(row["split"] for row in rows))
    with open(output, "w", encoding="utf-8") as file:
        json.dump(rows, file)


if __name__ == "__main__":
    main()
