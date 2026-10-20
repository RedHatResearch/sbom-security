#!/usr/bin/env python3
"""A baseline extractor that copies a CVE record's structured fields and reads no text.

It shows what the dataset measures. Records whose structured fields are filled in well
come out right, and records that keep their facts in prose come out wrong. Anything
better has to read the description.

It is also the example of both ways the runner reaches a tool: as a command, or as a
service the records are posted to.

    python3 evaluate.py --command "python3 fields_only.py"

    python3 fields_only.py --serve 8000
    python3 evaluate.py --url http://127.0.0.1:8000
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
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


class _Answering(BaseHTTPRequestHandler):
    """Answers each record posted to it, the way the runner's --url expects."""

    def do_POST(self) -> None:  # pylint: disable=invalid-name
        length = int(self.headers.get("Content-Length") or 0)
        try:
            record = json.loads(self.rfile.read(length))
        except ValueError:
            self.send_error(400, "the body is not JSON")
            return
        body = json.dumps(extract(record)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_server(port: int) -> HTTPServer:
    """Return a server answering records posted to it, reachable from this machine only."""
    return HTTPServer(("127.0.0.1", port), _Answering)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument(
        "--serve",
        type=int,
        metavar="PORT",
        help="answer records posted to this port, rather than one on standard input",
    )
    options = parser.parse_args()
    if options.serve is None:
        json.dump(extract(json.load(sys.stdin)), sys.stdout)
        return
    with make_server(options.serve) as server:
        print(f"Answering on http://127.0.0.1:{options.serve}", file=sys.stderr)
        server.serve_forever()


if __name__ == "__main__":
    main()
