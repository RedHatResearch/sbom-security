#!/usr/bin/env python3
"""A baseline extractor that copies a CVE record's structured fields and reads no text.

It shows what the dataset measures. Records whose structured fields are filled in well
come out right, and records that keep their facts in prose come out wrong. Anything
better has to read the description.

    python3 evaluate.py --command "python3 fields_only.py"
"""

import json
import sys
from typing import Any


def extract(record: dict[str, Any]) -> dict[str, Any]:
    """Answer from a record's structured fields alone."""
    metadata = record.get("cveMetadata") or {}
    cna = (record.get("containers") or {}).get("cna") or {}

    affected = []
    for item in cna.get("affected") or []:
        product = item.get("packageName") or item.get("product")
        if not product or product.lower() == "n/a":
            continue
        ranges, versions = [], []
        for version in item.get("versions") or []:
            if version.get("status") != "affected":
                continue
            start = version.get("version") or "0"
            if version.get("lessThan"):
                ranges.append({"introduced": start, "fixed": version["lessThan"]})
            elif version.get("lessThanOrEqual"):
                ranges.append({"introduced": start, "last_affected": version["lessThanOrEqual"]})
            elif start[0].isdigit():
                # A single version. Anything starting otherwise is prose this cannot read.
                versions.append(start)
        if not ranges and not versions and item.get("defaultStatus") == "unaffected":
            continue  # listed only to say it is not affected
        affected.append(
            {
                "product": product,
                "purl": item.get("packageURL"),
                "ranges": ranges,
                "versions": versions,
            }
        )

    cwe = [
        description["cweId"]
        for problem in cna.get("problemTypes") or []
        for description in problem.get("descriptions") or []
        if description.get("cweId")
    ]
    return {
        "id": metadata.get("cveId"),
        "status": (metadata.get("state") or "").lower(),
        "replaced_by": None,
        "affected": affected,
        "cwe": cwe,
    }


if __name__ == "__main__":
    json.dump(extract(json.load(sys.stdin)), sys.stdout)
