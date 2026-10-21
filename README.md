# php2shell-scan

A **non-exploiting, version-based checker** for the pair of critical PHP-core
RCE vulnerabilities disclosed on **2026-10-21** (nicknamed "php2shell").

| CVE | Title | CWE |
|---|---|---|
| **CVE-2026-109618** | RCE via OOM corruption | CWE-416 (use-after-free) |
| **CVE-2026-109619** | RCE via stale global state | CWE-416 (use-after-free) |

The tool reads a **declared** PHP version (from a local binary, an HTTP header,
or a value you supply) and compares it against the version ranges of the
referenced advisories. It **runs no exploit**, collects no configuration
(php.ini / FPM / WAF), isolates nothing and modifies nothing. It reports an
**exposure level**, never a proof of vulnerability or of a fix.

> Core rule: no detection, or any doubt, yields `UNDETERMINED` — never a bare
> "not vulnerable".

## Requirements

- **Standard library only** — no third-party dependencies.
- **Verified during development on:** CPython **3.14.7** (the interpreter
  available in the development environment). Automated tests are not included in
  this public distribution.
- **Inferred minimum: Python 3.7**, from code inspection only — the code relies
  on `subprocess.run(capture_output=...)` (3.7), guaranteed `dict` ordering
  (3.7), and PEP 563 deferred annotations (`from __future__ import annotations`).
  **Python 3.7–3.13 have not been executed/verified** here; treat the 3.7
  minimum as unverified until tested on those versions.

## Usage

```bash
# Manual: evaluate a strict X.Y.Z version string (no execution)
python3 php2shell_scan.py --version 8.3.35

# Local: scan PATH for PHP binaries with known names (partial inventory)
python3 php2shell_scan.py --local

# Local, a specific binary (e.g. the FPM actually serving the site)
python3 php2shell_scan.py --php-bin /usr/sbin/php-fpm8.3

# Remote: fingerprint your own site via HTTP headers (origin-locked)
python3 php2shell_scan.py --url https://my-site.example

# Verbose: full detail (evidence, limits, per-binary, redirects, mitigations)
python3 php2shell_scan.py --url https://my-site.example --verbose

# JSON: stable machine-readable output
python3 php2shell_scan.py --local --json
```

By default the report is concise (target, detected version, verdict, short
explanation, recommended action). `--verbose` adds full detail; `--json` emits
structured data.

## Verdicts and exit codes

| Verdict (stable JSON value) | Exit | Meaning |
|---|---|---|
| `POTENTIALLY_AFFECTED` | `2` | Declared version within an affected range → verify and fix |
| `OUTSIDE_KNOWN_AFFECTED_RANGE` | `0` | Declared version outside the known affected ranges (does **not** prove the web runtime is patched) |
| `UNDETERMINED` | `3` | Unknown/incomplete version, uncovered pre-release, unrecognized suffix, branch outside reference data, or collection failure |

Machine-readable **verdict values and JSON keys are stable** and will not change
silently; explanatory sentences may evolve. The JSON also carries
`tool_version`, `schema_version`, `reference_data_updated_at` and
`detection_method` (`manual` / `local` / `remote`).

## Affected versions (per the referenced advisories)

| PHP family | Status | Fixed in |
|---|---|---|
| 5.x, 7.x, 8.0.x, 8.1.x | affected, end of upstream support | vendor/source backport, no published version number |
| 6.x | mentioned in the advisory — documentary anomaly (PHP 6 was never released) → `UNDETERMINED` | — |
| 8.2.x | affected if `< 8.2.35` | **8.2.35** |
| 8.3.x | affected if `< 8.3.36` | **8.3.36** |
| 8.4.x | affected if `< 8.4.27` | **8.4.27** |
| 8.5.x | affected if `< 8.5.12` | **8.5.12** |

## Recognized vendor suffix formats

Only a **small, explicit allowlist** of distribution revision suffixes is
recognized (validated against the whole suffix). These are examples, **not
complete Debian/Ubuntu/EL support**:

| Format | Example |
|---|---|
| `-<rev>+deb<...>` | `8.3.35-1+deb12u1` |
| `-<rev>ubuntu<...>` | `8.3.35-1ubuntu3.1` |
| `-<rev>.el<N>` (optional `_<N>`) | `8.3.35-1.el9`, `8.3.35-1.el9_3` |

A recognized suffix is only used to read the **upstream** triplet; it **never
proves a backported fix is present**. **Any other suffix** (another distro,
`+build5`, `+garbage`, pre-release markers like `+dev`/`RC1`, etc.) deliberately
yields `UNDETERMINED` rather than a silent comparison.

## Important limitations

- **Declared HTTP versions** are untrusted: a header can be disabled, spoofed,
  or stripped by an intermediary. Cross-origin redirects are refused and the
  blocked destination is reported separately (`blocked_redirect_target`), never
  contacted.
- **Vendor backports**: a distribution can fix the flaw without changing the
  version number, so an affected-looking number may already be patched —
  `vendor_patch_status` is always `NOT_VERIFIED`.
- **Partial PATH inventory**: `--local` only finds PHP binaries with known names
  in `PATH`. It does not cover containers, installs outside `PATH`, or the
  active web runtime.
- **CLI vs web runtime**: the binary you query (or `php -v`) is not necessarily
  the SAPI (PHP-FPM / mod_php) that actually serves your site.
- **Temporary mitigations** (e.g. `session.upload_progress.enabled = Off`,
  blocking `multipart` requests) are **not qualified by CERT-FR** and **do not
  establish that either CVE is patched**. Only installing a fixed package does.

## Authorized use only

Use this tool **only** on systems you own or are explicitly authorized to test.

## References

- CERT-FR: <https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-014>
- PHP: <https://www.php.net/archive/2026.php>
- php-src advisories: GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp

**Reference-data update date:** `2026-10-21` (keep the version ranges in
`php2shell_scan.py` aligned with the advisories above).

## License

Released under the [MIT License](LICENSE) — Copyright (c) 2026 the php2shell-scan contributors.
