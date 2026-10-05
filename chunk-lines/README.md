# Afterimage / Chunk Lines

32 small offline cases compare the real urllib3 2.7.0 and 2.8.0 streaming implementations for published **CVE-2026-97689**. Reviewed 5 October 2026. Part of [Afterimage](https://github.com/SSH-PuR66/afterimage).

The [maintainer advisory](https://github.com/urllib3/urllib3/security/advisories/GHSA-vxq7-64xx-v4gw) lists urllib3 `>=1.10.3, <2.8.0` as affected and 2.8.0 as the first fixed release. Credit belongs to pquentin, coordinator, and illia-v, remediation reviewer. The [fix commit](https://github.com/urllib3/urllib3/commit/cd770b059b543be29298ea5c52afb0b1b090f5ed) bounds size and trailer lines. [Release notes](https://github.com/urllib3/urllib3/releases/tag/2.8.0) describe other changes.

## Observations

Each release runs eight fixtures through both `stream()` and `read_chunked()`: an ordinary body, size lines at 65,535/65,536/65,537/65,538 bytes, trailers at 65,536/65,538 bytes, and a 65,537-byte body. Line lengths include CRLF.

2.7.0 accepts all of these framing lines. 2.8.0 accepts lines through 65,536 bytes, reads at most 65,537, and rejects larger size lines before any body read. Oversized trailers fail after a body byte has already been yielded. Both releases accept the body larger than the line cap, showing that this guard concerns framing rather than total body size.

`results.json` contains per-case outcomes, read sizes, body lengths and digests, close state, package identity, environment, and source hashes. It records 32 passes and zero case-time network attempts. urllib3's import-time IPv6 probe is blocked by the audit guard and recorded separately.

## Reproduce

Python 3.10+ and its standard library. From this directory, obtain the two public wheels once:

```sh
python -m pip download --only-binary=:all: --no-deps --dest .cache/wheels urllib3==2.7.0
python -m pip download --only-binary=:all: --no-deps --dest .cache/wheels urllib3==2.8.0
python run_boundary.py
python -m unittest discover -p 'test_*.py' -v
```

The runner itself makes no downloads. It checks exact wheel size and SHA-256 against `pinned-releases.json`, imports each wheel directly in an isolated child process, and disables site packages. The wheel's `response.py` digest was also checked against its pinned upstream release commit. Tests reject a tampered wheel, stale evidence, and a mismatch between the published observations and a fresh local run.

Fixtures use counted `BytesIO` files and `http.client.HTTPResponse`; the urllib3 parser is unmodified. Socket creation and DNS are blocked. Input is capped at 70,000 bytes per case; the largest fixture is 65,551 bytes. The child has a ten-second timeout and a fixed iteration limit. No server, stress loop, or unbounded input generator is used.

## Scope and attribution

This verifies the framing cap, accepted boundary, rejection order, trailer behavior, and ordinary response controls. It does not demonstrate memory exhaustion, network read-ahead, TLS behavior, the requests wrapper, decompression, application exploitability, a new discovery, or a CVE assignment. The advisory's remediation paragraph currently says 66,536; its impact section, fixed implementation, and these bounded checks use 65,536.

Sergio Rodriguez's contribution is AI-assisted independent regression, source-history comparison, evidence recording, and presentation. Upstream discovery and remediation credit remain with the named maintainers. The earlier documentation-only review is superseded by the narrow local evidence here; broader application impact remains untested.

Public artifacts: `index.html`, `style.css`, `README.md`, `source-review.json`, `pinned-releases.json`, `boundary_fixture.py`, `run_boundary.py`, `test_boundary.py`, and `results.json`. Cached wheels and earlier unfinished work are excluded.
