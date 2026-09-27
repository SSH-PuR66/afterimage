# CVE Replay: the redirect header boundary

**CVE-2026-44431 · urllib3 2.6.3 → 2.7.0 · reproduced 27 September 2026**

A request carries three sensitive headers to one origin. A redirect changes the destination. Does the next request still carry them?

This independent regression runs the real redirect implementation from two exact urllib3 releases. Version 2.6.3 retains all three headers through the affected low-level API. Version 2.7.0 removes them. A benign header survives, and ordinary requests still work.

## Measured result

| Fixture | urllib3 2.6.3 | urllib3 2.7.0 |
|---|---|---|
| Low-level cross-origin redirect | 3 sensitive headers retained | 0 retained |
| Same case with lowercase names | 3 retained | 0 retained |
| High-level API control | 0 retained | 0 retained |
| Direct 200 response | 3 retained as intended | 3 retained as intended |
| Redirect explicitly disabled | One call; 302 returned | One call; 302 returned |
| Custom removal set adds benign marker | All 4 headers retained | All 4 removed |

**12/12 scenario expectations passed.** Each scenario also checks response status, transport call count, the initial header set, the benign-header result, and that the caller's headers were not mutated. The vulnerable outcome is an expected baseline result, not a passing security check.

[Machine-readable results](results.json) include the captured arguments, exact wheel hashes, runtime, test-source hashes, attribution, and reproduction time.

## The published issue

The [upstream advisory](https://github.com/urllib3/urllib3/security/advisories/GHSA-qccp-gfcp-xxvc), published 7 May 2026, identifies an information-exposure issue in urllib3's proxied low-level redirect path. It lists versions `>=1.23, <2.7.0` as affected. Calling `ProxyManager.connection_from_url(...).urlopen(..., assert_same_host=False)` could carry configured sensitive headers into a redirected request to another origin. The high-level manager API already removed them.

The [upstream fix](https://github.com/urllib3/urllib3/commit/5ec0de499b9166ca71c65ab04f2a7e4eb0d66fcc) applies `Retry.remove_headers_on_redirect` before the recursive low-level request. Our lowercase-header case follows the upstream regression's attention to header-name casing. The custom-removal case checks that the rule honors the configured set, beyond only the three default names.

The advisory credits **christos-cantina-security** as reporter, **illia-v** as coordinator, and **sethmlarson** as remediation reviewer. Sergio Rodriguez's contribution here is the independent offline harness and before/after analysis. This is a reproduction of their published CVE.

## Reproduce the fixture

Use Python 3.10 or later. No pip install or virtual environment is necessary: each version is imported directly from its pure-Python wheel in a fresh isolated subprocess.

From the portfolio repository root:

```powershell
python -B ./labs/cve-replay/run_replay.py --fetch
python -B ./labs/cve-replay/run_replay.py
```

The first command downloads the two exact wheels into the lab's ignored `.cache/wheels/` directory and checks their SHA-256 hashes against the manifest. The second command uses that cache without downloading. For a standalone source checkout, run `python -B run_replay.py --fetch`, then the same command without `--fetch`. `--cache` accepts a different local cache directory.

## Where the mock begins

`HTTPConnectionPool._make_request` is replaced with a two-response transport: a 302 with a fixed location, then a 200. The fixture captures the arguments reaching that boundary. urllib3's parsing, retry policy, header filtering, and recursive redirect handling execute unchanged from the selected wheel.

All destinations are fixed reserved `.invalid` names; all header values begin with `DUMMY`. Socket construction and DNS functions raise immediately. The library's import-time IPv6 capability probe is denied and recorded separately; the replay scenarios attempt no network operations. There is no listening server or live target.

This validates redirect argument handling. It does not measure end-to-end proxy traffic. Version 2.7.0 is the first fix for this particular CVE; this historical comparison is not a recommendation to select it over newer supported releases.

## Sources and attribution

- [Maintainer advisory / CVE-2026-44431](https://github.com/urllib3/urllib3/security/advisories/GHSA-qccp-gfcp-xxvc)
- [Upstream fix and regression tests](https://github.com/urllib3/urllib3/commit/5ec0de499b9166ca71c65ab04f2a7e4eb0d66fcc)
- [Affected release source](https://github.com/urllib3/urllib3/blob/2.6.3/src/urllib3/connectionpool.py)
- [Fixed release source](https://github.com/urllib3/urllib3/blob/2.7.0/src/urllib3/connectionpool.py)
- [urllib3 2.7.0 release notes](https://github.com/urllib3/urllib3/releases/tag/2.7.0)
- [Pinned package URLs, PyPI metadata, and hashes](pinned-releases.json)

The fixture scripts and analysis are original portfolio work. urllib3 is an upstream project distributed under its [MIT license](https://github.com/urllib3/urllib3/blob/2.7.0/LICENSE.txt); its code and release wheels are not redistributed in the portfolio source archive. They are downloaded separately from PyPI and imported unchanged for the experiment.
