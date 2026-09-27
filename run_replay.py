"""Fetch two hash-pinned pure-Python wheels, then run each in an offline process."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
DEFAULT_CACHE = HERE / ".cache" / "wheels"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="Download missing exact upstream wheels from PyPI")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path, default=HERE / "results.json")
    args = parser.parse_args()
    manifest = json.loads((HERE / "pinned-releases.json").read_text(encoding="utf-8"))
    args.cache.mkdir(parents=True, exist_ok=True)
    results = []
    for release in manifest["releases"]:
        wheel = args.cache / release["filename"]
        if not wheel.exists():
            if not args.fetch:
                raise SystemExit("Pinned wheel missing. Run once with --fetch, then rerun offline.")
            with urlopen(release["url"], timeout=30) as response:
                data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != release["sha256"]:
                raise SystemExit("Downloaded wheel failed size/hash validation")
            wheel.write_bytes(data)
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != release["sha256"]:
            raise SystemExit("Cached wheel does not match its pinned SHA-256")
        child = subprocess.run([sys.executable, "-I", "-B", str(HERE / "replay_fixture.py"),
                                "--wheel", str(wheel.resolve())],
                               text=True, encoding="utf-8", capture_output=True, timeout=20)
        if child.returncode:
            raise SystemExit(child.stderr or child.stdout)
        results.append(json.loads(child.stdout))
    report = {
        "schema_version": 1,
        "title": "A redirect crosses the header boundary",
        "cve": manifest["cve"],
        "ghsa": "GHSA-qccp-gfcp-xxvc",
        "advisory_published_at": "2026-05-07T16:33:54Z",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "advisory": manifest["advisory"],
        "upstream_fix": manifest["upstream_fix"],
        "attribution": {"reporter": "christos-cantina-security", "coordinator": "illia-v",
                        "remediation_reviewer": "sethmlarson", "portfolio_work": "Independent offline regression; original test harness."},
        "runtime": {"python": platform.python_version(), "platform": platform.system()},
        "method": "Exact urllib3 release wheels imported directly in isolated subprocesses. Real redirect implementation; HTTPConnectionPool._make_request replaced by fixed responses and argument capture. Sockets and DNS disabled.",
        "cases_per_version": 6,
        "total_cases_passed": sum(row["cases_passed"] for row in results),
        "network_attempts_during_replay": sum(row["network_attempts"] for row in results),
        "versions": results,
        "source_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                          for name in ("replay_fixture.py", "run_replay.py", "pinned-releases.json")},
        "limits": ["A known upstream CVE, not a new discovery or CVE assignment.",
                   "Transport is mocked; this verifies redirect argument handling, not end-to-end proxy networking.",
                   "All header values are DUMMY strings and all destinations use reserved .invalid names.",
                   "Version 2.7.0 fixes this CVE; it is not a statement about all current security issues."],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cve": report["cve"], "cases_passed": report["total_cases_passed"],
                      "network_attempts": report["network_attempts_during_replay"],
                      "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
