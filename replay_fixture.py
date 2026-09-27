"""Offline regression for CVE-2026-44431 against an exact upstream wheel.

The real redirect implementation runs. Only the transport is replaced. All
socket creation and name resolution are disabled before urllib3 is imported.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import sys
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = "http://origin-a.invalid/start"
DESTINATION = "http://origin-b.invalid/final"
PROXY = "http://proxy.invalid:8080"
SENSITIVE = {"authorization", "cookie", "proxy-authorization"}
MARKERS = {
    "Authorization": "DUMMY_AUTHORIZATION",
    "Cookie": "DUMMY_COOKIE=1",
    "Proxy-Authorization": "DUMMY_PROXY_AUTHORIZATION",
    "X-Research-Control": "DUMMY_BENIGN_CONTROL",
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(wheel):
    manifest = json.loads((HERE / "pinned-releases.json").read_text(encoding="utf-8"))
    release = next((row for row in manifest["releases"] if row["filename"] == wheel.name), None)
    require(release is not None, "Only the two manifest-pinned wheels are allowed")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    require(digest == release["sha256"], "Wheel SHA-256 does not match the pinned release")
    sys.path.insert(0, str(wheel.resolve()))
    blocked_network_attempts = []

    def blocked(*args, **kwargs):
        blocked_network_attempts.append("socket_or_dns_attempt")
        raise RuntimeError("This fixture forbids sockets and DNS")

    guards = [patch.object(socket, name, blocked) for name in
              ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex")]
    for guard in guards:
        guard.start()
    try:
        import urllib3
        from urllib3.connectionpool import HTTPConnectionPool
        from urllib3.response import HTTPResponse
        from urllib3.util import Retry
        require(urllib3.__version__ == release["version"], "A different urllib3 package was imported")
        require(str(wheel.resolve()) in urllib3.__file__, "Import escaped the pinned wheel")
        # urllib3 probes IPv6 support during import. The guard denies that probe
        # before a socket exists; record it separately from replay operations.
        blocked_import_probes = len(blocked_network_attempts)
        blocked_network_attempts.clear()

        results = []
        scenarios = [
            ("low_level_cross_origin", "low", False, True, True, False),
            ("low_level_lowercase_headers", "low", True, True, True, False),
            ("high_level_cross_origin_control", "high", False, True, True, False),
            ("direct_200_positive_control", "low", False, False, True, False),
            ("redirect_disabled_control", "low", False, True, False, False),
            ("custom_removal_set", "low", False, True, True, True),
        ]
        for name, level, lowercase, redirect_response, follow, custom in scenarios:
            captured = []
            sent_headers = {key.lower() if lowercase else key: value for key, value in MARKERS.items()}
            original_headers = dict(sent_headers)

            def transport(pool, connection, method, url, **kwargs):
                require(url in {SOURCE, DESTINATION}, "Transport received an unexpected destination")
                require(method == "GET", "Only the fixed GET fixture is allowed")
                require(len(captured) < 2, "Redirect fixture exceeded its two-call limit")
                headers = dict(kwargs.get("headers") or {})
                captured.append({"url": url, "headers": headers})
                status = 302 if len(captured) == 1 and redirect_response else 200
                return HTTPResponse(
                    body=b"DUMMY_RESPONSE" if status == 200 else b"",
                    status=status,
                    headers={"Location": DESTINATION} if status == 302 else {},
                    preload_content=True,
                    request_method=method,
                    retries=kwargs.get("retries"),
                )

            removal = SENSITIVE | {"x-research-control"} if custom else SENSITIVE
            retries = Retry(total=1, redirect=1, remove_headers_on_redirect=removal)
            with patch.object(HTTPConnectionPool, "_make_request", transport):
                with urllib3.ProxyManager(PROXY) as manager:
                    if level == "low":
                        pool = manager.connection_from_url(SOURCE)
                        response = pool.urlopen("GET", SOURCE, headers=sent_headers,
                                                retries=retries, redirect=follow,
                                                assert_same_host=False)
                    else:
                        response = manager.request("GET", SOURCE, headers=sent_headers,
                                                   retries=retries, redirect=follow)
            expected_calls = 2 if redirect_response and follow else 1
            require(len(captured) == expected_calls, f"{name}: unexpected transport call count")
            require(response.status == (302 if redirect_response and not follow else 200),
                    f"{name}: wrong terminal response")
            require(sent_headers == original_headers, f"{name}: caller headers were mutated")
            first = {key.lower(): value for key, value in captured[0]["headers"].items()}
            final = {key.lower(): value for key, value in captured[-1]["headers"].items()}
            require(SENSITIVE <= first.keys(), f"{name}: synthetic headers missing from first request")
            stripped = expected_calls == 2 and (level == "high" or release["version"] == "2.7.0")
            expected_sensitive = set() if stripped else SENSITIVE
            require(SENSITIVE.intersection(final) == expected_sensitive,
                    f"{name}: unexpected sensitive-header boundary behavior")
            benign_should_survive = not (stripped and custom)
            require(("x-research-control" in final) == benign_should_survive,
                    f"{name}: benign/custom header control failed")
            results.append({
                "id": name, "api": level, "status": response.status,
                "transport_calls": len(captured),
                "first_request_sensitive_headers": sorted(SENSITIVE.intersection(first)),
                "final_request_sensitive_headers": sorted(SENSITIVE.intersection(final)),
                "benign_header_retained": "x-research-control" in final,
                "caller_headers_unchanged": sent_headers == original_headers,
                "captured_calls": captured,
                "expectation_passed": True,
            })
        require(not blocked_network_attempts, "A network operation was attempted")
        return {"version": urllib3.__version__, "wheel_sha256": digest,
                "status_for_this_cve": release["status_for_this_cve"],
                "cases": results, "cases_passed": len(results),
                "network_attempts": len(blocked_network_attempts),
                "blocked_import_capability_probes": blocked_import_probes,
                "socket_creation_disabled": True}
    finally:
        for guard in reversed(guards):
            guard.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.wheel), indent=2))
