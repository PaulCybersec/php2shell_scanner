#!/usr/bin/env python3
"""
php2shell_scan — NON-EXPLOITING evaluator of declared PHP versions, for the pair
of PHP-core RCE vulnerabilities disclosed on 2026-10-21 (nicknamed "php2shell").

Scanned CVEs (scan metadata, assigned by the PHP Group CNA):
  * CVE-2026-109618 — "RCE via OOM corruption" (CWE-416).
  * CVE-2026-109619 — "RCE via stale global state" (CWE-416).

WHAT THIS TOOL DOES / DOES NOT DO
  It reads A DECLARED VERSION (local binary, HTTP header, or supplied value) and
  compares it against the ranges of a security advisory. It therefore measures
  an EXPOSURE LEVEL, never a proof of vulnerability or of a fix. In particular it
  collects NO configuration (php.ini / FPM / WAF), runs no attack, isolates
  nothing and modifies nothing.

  Core rule: no detection, or any doubt, yields UNDETERMINED — never a
  reassuring "not vulnerable".

Reference advisories (keep up to date):
  * CERTFR-2026-ALE-014: https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-014
  * PHP release 2026-10-21: https://www.php.net/archive/2026.php
  * GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (php-src)

Use ONLY on systems you own or are authorized to test.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

# --------------------------------------------------------------------------- #
# Stable identifiers (machine-readable; do not change silently once published).
# --------------------------------------------------------------------------- #
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1"
# As-of date of the version reference data below (support status is dated: a
# branch listed as maintained today will not stay so indefinitely).
REFERENCE_DATA_UPDATED_AT = "2026-10-21"

# Version reference data — keep aligned with the cited official advisories.
# MAINTAINED branches: fixed starting at the indicated version.
FIX_BY_BRANCH = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

CVES_SEARCHED = ["CVE-2026-109618", "CVE-2026-109619"]
# This tool claims NO CVSS score: it points to the referenced advisories, which
# are authoritative and must be consulted for severity.
CVE_SEVERITY_NOTE = (
    "CVSS score: refer to the referenced advisories (not claimed by this tool).")

ADVISORY_REFERENCES = [
    "https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-014",
    "https://www.php.net/archive/2026.php",
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
]

# Verdicts (exposure level inferred from a declared version). STABLE values.
AFFECTED = "POTENTIALLY_AFFECTED"              # exit 2
OUT_OF_RANGE = "OUTSIDE_KNOWN_AFFECTED_RANGE"  # exit 0
UNDETERMINED = "UNDETERMINED"                  # exit 3

EXIT_CODE = {AFFECTED: 2, OUT_OF_RANGE: 0, UNDETERMINED: 3}

# Severity ordering for local aggregation (a clean result must never mask an
# affected or undetermined one).
_SEVERITY_RANK = {AFFECTED: 2, UNDETERMINED: 1, OUT_OF_RANGE: 0}


# --------------------------------------------------------------------------- #
# Version parsing
# --------------------------------------------------------------------------- #
_TRIPLET_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(.*)$")
_MANUAL_RE = re.compile(r"^\d+\.\d+\.\d+\S*$")
_PRERELEASE_RE = re.compile(
    r"^[-._+]?(rc|alpha|beta|dev|snapshot|pre)",
    re.IGNORECASE,
)
# Vendor/distribution revision suffixes: a SMALL allowlist of documented, tested
# formats, validated with fullmatch (the whole suffix must match). A recognized
# format NEVER proves a backported fix is present. Anything else is
# "unrecognized" and yields UNDETERMINED rather than a silent comparison.
_VENDOR_SUFFIX_RES = (
    re.compile(r"-\d+\+deb[0-9a-z.+~]+", re.IGNORECASE),    # Debian:  -1+deb12u1
    re.compile(r"-\d+ubuntu[0-9a-z.+~]+", re.IGNORECASE),   # Ubuntu:  -1ubuntu3.1
    re.compile(r"-\d+\.el\d+(?:_\d+)?", re.IGNORECASE),     # RHEL/EL: -1.el9, -1.el9_3
)
# Explicit PHP token with a left boundary so a product whose name ENDS with
# "PHP" (e.g. "NotPHP/8.3.35") is not matched.
_PHP_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])PHP[/ ]v?(\d+\.\d+\.\d+[^\s,;()]*)", re.IGNORECASE)


def classify_suffix(suffix: str) -> str:
    """none | prerelease | vendor | unrecognized (vendor via strict fullmatch)."""
    if not suffix:
        return "none"
    if _PRERELEASE_RE.match(suffix):
        return "prerelease"
    if any(rx.fullmatch(suffix) for rx in _VENDOR_SUFFIX_RES):
        return "vendor"
    return "unrecognized"


def split_version(raw: str) -> dict:
    """Split a string starting with an X.Y.Z triplet.

    Returns {ok, raw, upstream:(M,m,p)|None, suffix, suffix_class, is_prerelease}.
    NEVER fills a missing component with .0.
    """
    raw = (raw or "").strip()
    m = _TRIPLET_RE.match(raw)
    if not m:
        return {"ok": False, "raw": raw, "upstream": None, "suffix": "",
                "suffix_class": "none", "is_prerelease": False}
    upstream = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    suffix = m.group(4) or ""
    sclass = classify_suffix(suffix)
    return {"ok": True, "raw": raw, "upstream": upstream, "suffix": suffix,
            "suffix_class": sclass, "is_prerelease": sclass == "prerelease"}


def parse_manual(raw: str) -> dict:
    """STRICT --version mode: require a full triplet, reject banners."""
    raw = (raw or "").strip()
    if not _MANUAL_RE.match(raw):
        return {"ok": False, "raw": raw, "upstream": None, "suffix": "",
                "suffix_class": "none", "is_prerelease": False}
    return split_version(raw)


def extract_php_tokens(text: str):
    """Extract every version token explicitly attached to a standalone 'PHP'."""
    return _PHP_TOKEN_RE.findall(text or "")


# --------------------------------------------------------------------------- #
# Evaluation (assess)
# --------------------------------------------------------------------------- #
def _model(verdict, parsed, *, detail, support_status, fixed_in=None,
           support_note=None, anomaly=None):
    up = parsed.get("upstream")
    return {
        "version_raw": parsed.get("raw", ""),
        "upstream_version": ".".join(map(str, up)) if up else None,
        "version_suffix": parsed.get("suffix", ""),
        "suffix_class": parsed.get("suffix_class", "none"),
        "verdict": verdict,
        "upstream_support_status": support_status,
        "vendor_patch_status": "NOT_VERIFIED",
        "fixed_in": fixed_in,
        "detail": detail,
        "support_note": support_note,
        "anomaly": anomaly,
        "cves_searched": list(CVES_SEARCHED),
    }


_VENDOR_SUFFIX_NOTE = ("Recognized vendor revision format; this does not prove "
                       "the backported fix is actually present.")


def assess(parsed: dict) -> dict:
    """Evaluate an already-parsed declared version and return the result model."""
    if not parsed.get("ok"):
        return _model(
            UNDETERMINED, parsed,
            detail="Unreadable or incomplete version (X.Y.Z triplet required).",
            support_status="unknown",
        )

    up = parsed["upstream"]
    up_str = ".".join(map(str, up))
    suffix = parsed["suffix"]
    sclass = parsed.get("suffix_class", "none")

    if sclass == "prerelease":
        return _model(
            UNDETERMINED, parsed,
            detail=(f"Pre-release detected ({up_str}{suffix}): not covered by a "
                    f"specific rule, result deliberately undetermined."),
            support_status="unknown (pre-release)",
        )
    if sclass == "unrecognized":
        return _model(
            UNDETERMINED, parsed,
            detail=(f"Unrecognized version suffix ({suffix!r} after {up_str}): "
                    f"cannot conclude reliably."),
            support_status="unknown (unrecognized suffix)",
        )

    vendor_note = _VENDOR_SUFFIX_NOTE if sclass == "vendor" else None
    major, minor, _ = up
    branch = (major, minor)

    # Explicitly referenced maintained branches.
    if branch in FIX_BY_BRANCH:
        fix = FIX_BY_BRANCH[branch]
        fix_str = ".".join(map(str, fix))
        if up < fix:
            return _model(
                AFFECTED, parsed,
                detail=(f"Upstream version {up_str} is earlier than the fix "
                        f"{fix_str} for its branch: within the affected range."),
                support_status="supported (maintained branch)",
                fixed_in=fix_str, support_note=vendor_note,
            )
        return _model(
            OUT_OF_RANGE, parsed,
            detail=(f"Upstream version {up_str} >= fix {fix_str}: outside the "
                    f"known affected range. Does not prove the web runtime is "
                    f"patched."),
            support_status="supported (maintained branch)",
            fixed_in=fix_str, support_note=vendor_note,
        )

    # 6.x family: mentioned in the advisory although PHP 6 was never released.
    if major == 6:
        return _model(
            UNDETERMINED, parsed,
            detail=("6.x family mentioned in CERTFR-2026-ALE-014: documentary "
                    "anomaly to be clarified (PHP 6 was never released)."),
            support_status="out of upstream support",
            anomaly="6.x mention in the advisory to be clarified",
        )

    # Older families explicitly listed as affected (5.x, 7.x, 8.0, 8.1).
    if major in (5, 7) or (major == 8 and minor in (0, 1)):
        return _model(
            AFFECTED, parsed,
            detail=(f"Family {major}.{minor} listed as affected by "
                    f"CERTFR-2026-ALE-014; end of upstream support."),
            support_status="end of upstream support",
            support_note=(
                "A fix may exist via a vendor/distribution backport or a PHP "
                "source-backport (branches PHP-7.4/8.0/8.1-"
                "CVE-2026-109618-109619). Installed package status: NOT_VERIFIED. "
                "No fixed version number was published for these branches."),
        )

    # Out of reference data (e.g. 8.6+, 9.x, 4.x): no reassuring extrapolation.
    return _model(
        UNDETERMINED, parsed,
        detail=(f"Branch {major}.{minor} is outside the known version reference "
                f"data of the advisory: undetermined result (neither affected "
                f"nor proven safe)."),
        support_status="unknown",
    )


# --------------------------------------------------------------------------- #
# Reliability limits by source
# --------------------------------------------------------------------------- #
LIMITS_BY_SOURCE = {
    "remote": (
        "declarative version read from an HTTP header (can be disabled, spoofed, "
        "or stripped by an intermediary); a backported vendor fix may neutralize "
        "the flaw without changing this number."),
    "local": (
        "number reported by the queried binary; a backported vendor fix may fix "
        "the flaw without changing this number, and this binary is not "
        "necessarily the SAPI (PHP-FPM/mod_php) serving the site."),
    "manual": (
        "version supplied by hand, not verified on a real system."),
}

LOCAL_INVENTORY_NOTE = (
    "Partial inventory: PHP binaries with known names found in PATH only. Does "
    "not cover containers, installations outside PATH, or the active web runtime.")

VERIFICATION_STEPS = (
    "Do not rely on the version number alone:\n"
    "  - Confirm the actually affected scope and the VENDOR PACKAGE status\n"
    "    (changelog / package revision), not just the upstream version.\n"
    "  - Depending on context, isolate or restrict exposure during remediation\n"
    "    (never automatically on the strength of a header alone).\n"
    "  - Install a package containing the fixes, or migrate to a maintained and\n"
    "    fixed branch (8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+).\n"
    "  - Restart the processes that actually serve PHP (PHP-FPM, Apache), then\n"
    "    verify the active web runtime and the full package version."
)

WORKAROUNDS = (
    "Temporary mitigations — DO NOT REPLACE the update, and NOT QUALIFIED by "
    "CERT-FR:\n"
    "  - php.ini: session.upload_progress.enabled = Off\n"
    "    PHP-FPM: php_admin_flag[session.upload_progress.enabled] = off\n"
    "    (reduces the attack surface for ONLY ONE of the two vulnerabilities; "
    "possible impact on uploads, to be validated).\n"
    "  - Block requests whose Content-Type is 'multipart', or at least monitor "
    "them (e.g. WAF).\n"
    "  This tool verifies NONE of these settings and generates no WAF rule."
)


# --------------------------------------------------------------------------- #
# Untrusted-text safety (header values and binary output are untrusted)
# --------------------------------------------------------------------------- #
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _sanitize(value, limit: int = 300) -> str:
    """Escape control chars (incl. newlines and terminal escapes) and truncate.

    Prevents a remote header or binary output from injecting fake report lines
    or terminal escape sequences. JSON uses json.dumps, which escapes these on
    its own, so sanitization is only applied to human-readable output.
    """
    s = value if isinstance(value, str) else str(value)
    s = _CTRL_RE.sub(lambda m: "\\x%02x" % ord(m.group(0)), s)
    if len(s) > limit:
        s = s[:limit] + "...(truncated)"
    return s


# --------------------------------------------------------------------------- #
# Detection — MANUAL
# --------------------------------------------------------------------------- #
def detect_manual(raw: str) -> dict:
    parsed = parse_manual(raw)
    result = assess(parsed)
    result["detection_method"] = "manual"
    result["source"] = f"manual input: {raw!r}"
    result["evidence"] = (f"version supplied as argument: {parsed['raw']}"
                          if parsed["ok"] else f"rejected input: {raw!r}")
    result["limitations"] = LIMITS_BY_SOURCE["manual"]
    result["detection_log"] = [f"--version {raw!r}"]
    return result


# --------------------------------------------------------------------------- #
# Detection — REMOTE (HTTP, non-destructive, origin-locked)
# --------------------------------------------------------------------------- #
USER_AGENT = "php2shell-scan/1.0 (+non-destructive version check)"
MAX_REDIRECTS = 5


def _origin(url: str):
    p = urllib.parse.urlsplit(url)
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()

    default_port = 443 if scheme == "https" else 80
    port = p.port if p.port is not None else default_port

    if not 1 <= port <= 65535:
        raise ValueError("Port out of range 1-65535")

    return (scheme, host, port)


class _RedirectRefused(Exception):
    """Raised by the redirect handler. Behavior keys off `kind`, not any text."""

    def __init__(self, kind, target, chain):
        super().__init__(kind)
        self.kind = kind          # "redirect_blocked" | "redirect_limit_exceeded"
        self.target = target
        self.chain = list(chain)


class _OriginLockedRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse cross-origin / looping redirects via a typed exception."""

    def __init__(self, origin):
        self._origin = origin
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        refusal = None
        if _origin(newurl) != self._origin:
            refusal = "redirect_blocked"
        elif len(self.chain) >= MAX_REDIRECTS:
            refusal = "redirect_limit_exceeded"
        if refusal:
            if fp is not None:
                try:
                    fp.close()  # release the 302 response body (avoid leak)
                except Exception:  # noqa: BLE001
                    pass
            raise _RedirectRefused(refusal, newurl, self.chain)
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _undet_remote(requested, final, detail, notes):
    r = assess({"ok": False, "raw": "", "upstream": None, "suffix": "",
                "suffix_class": "none", "is_prerelease": False})
    r["detection_method"] = "remote"
    r["detail"] = detail
    r["source"] = "HTTP header"
    r["evidence"] = None
    r["limitations"] = LIMITS_BY_SOURCE["remote"]
    r["requested_url"] = requested
    r["final_url"] = final
    r["detection_log"] = notes
    return r


def collect_php_tokens_from_headers(headers):
    """Collect (header, token) from ALL relevant repeated headers.

    HTTP allows multiple 'X-Powered-By'/'Server' headers; get_all() reads them
    all. Returns (tokens:list[(hdr,tok)], notes:list[str]).
    """
    tokens, notes = [], []
    if headers is None:
        return tokens, notes
    for hdr in ("X-Powered-By", "Server"):
        try:
            values = headers.get_all(hdr) or []
        except AttributeError:
            one = headers.get(hdr)
            values = [one] if one else []
        for val in values:
            notes.append(f"{hdr}: {val}")
            for tok in extract_php_tokens(val):
                tokens.append((hdr, tok))
    return tokens, notes


def detect_remote(url: str, timeout: float) -> dict:
    # Build without mangling the query: keep the exact path+query; if no path is
    # provided, query the origin root.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    # urlsplit().hostname/.port may raise ValueError on a malformed URL (invalid
    # port, broken IPv6 brackets, etc.): catch instead of crashing.
    try:
        p = urllib.parse.urlsplit(url)
        scheme, hostname = p.scheme, p.hostname
        path = p.path or "/"
        requested = urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, ""))
        origin = _origin(requested)
    except ValueError as exc:
        return _undet_remote(url, None, f"Malformed URL: {exc}",
                             [f"rejected URL: {url!r} ({exc})"])
    if scheme not in ("http", "https") or not hostname:
        return _undet_remote(url, None, "Invalid URL (http/https scheme and host required).",
                             [f"rejected URL: {url!r}"])

    handler = _OriginLockedRedirect(origin)
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(requested, headers={"User-Agent": USER_AGENT})

    notes = []
    try:
        with opener.open(req, timeout=timeout) as resp:
            headers = resp.headers
            final = resp.geturl()
            notes.append(f"HTTP {resp.status} on {final}")
    except _RedirectRefused as rr:
        if rr.chain:
            notes.append("Redirects followed before refusal: " + " -> ".join(rr.chain))
        notes.append(f"redirect refused ({rr.kind}) -> {rr.target} (not contacted)")
        detail = ("Collection interrupted: cross-origin redirect refused."
                  if rr.kind == "redirect_blocked"
                  else "Collection interrupted: too many redirects.")
        # final_url = last URL actually requested (never the blocked target).
        last_requested = handler.chain[-1] if handler.chain else requested
        r = _undet_remote(requested, last_requested, detail, notes)
        r["redirect_block_kind"] = rr.kind
        r["blocked_redirect_target"] = rr.target
        return r
    except urllib.error.HTTPError as exc:
        headers = exc.headers
        final = getattr(exc, "url", requested)
        code = exc.code
        exc.close()  # release the response body (avoids a socket leak)
        notes.append(f"HTTP {code} error — headers analyzed")
    except Exception as exc:  # noqa: BLE001
        return _undet_remote(requested, None, f"Collection failed: {exc}",
                             [f"request failed: {exc}"])

    if handler.chain:
        notes.append("Redirects (same origin): " + " -> ".join(handler.chain))

    # Collect explicit PHP tokens from ALL headers (including repeated ones).
    tokens, hdr_notes = collect_php_tokens_from_headers(headers)
    notes.extend(hdr_notes)

    distinct = sorted({tok for _, tok in tokens})
    if not distinct:
        return _undet_remote(
            requested, final,
            "No PHP version observed in the headers; cause undetermined "
            "(no PHP, header stripped by an intermediary, or expose_php=Off).",
            notes)
    if len(distinct) > 1:
        notes.append("Conflicting PHP tokens: " + ", ".join(distinct))
        r = _undet_remote(
            requested, final,
            "Conflicting PHP headers: no value retained "
            "(conflict reported, no silent choice).", notes)
        r["observations"] = [{"header": h, "version_raw": t} for h, t in tokens]
        return r

    raw = distinct[0]
    hdr_name = next(h for h, t in tokens if t == raw)
    result = assess(split_version(raw))
    result["detection_method"] = "remote"
    result["source"] = f"{hdr_name} header"
    result["evidence"] = f"{hdr_name} header advertises PHP/{raw}"
    result["limitations"] = LIMITS_BY_SOURCE["remote"]
    result["requested_url"] = requested
    result["final_url"] = final
    result["observations"] = [{"header": h, "version_raw": t} for h, t in tokens]
    result["detection_log"] = notes
    return result


# --------------------------------------------------------------------------- #
# Detection — LOCAL (scan PATH for known binary names, without masking affected)
# --------------------------------------------------------------------------- #
LOCAL_CANDIDATES = [
    "php",
    "php8.5", "php8.4", "php8.3", "php8.2", "php8.1", "php8.0",
    "php7.4", "php7.3", "php7.2", "php7.1", "php7.0",
    "php-fpm",
    "php-fpm8.5", "php-fpm8.4", "php-fpm8.3", "php-fpm8.2", "php-fpm8.1",
    "php-fpm8.0", "php-fpm7.4",
]


def _blank_parsed():
    return {"ok": False, "raw": "", "upstream": None, "suffix": "",
            "suffix_class": "none", "is_prerelease": False}


def _assess_binary(php_bin: str) -> dict:
    notes = []
    try:
        out = subprocess.run([php_bin, "-v"], capture_output=True, text=True,
                             timeout=15)
    except subprocess.TimeoutExpired as exc:
        r = assess(_blank_parsed())
        r["detection_method"] = "local"
        r["detail"] = f"Timed out running `{php_bin} -v`."
        r["evidence"] = None
        notes.append(f"{php_bin} -> timeout")
        r["binary"] = php_bin
        r["detection_log"] = notes
        return r
    except (OSError, subprocess.SubprocessError) as exc:
        r = assess(_blank_parsed())
        r["detection_method"] = "local"
        r["detail"] = f"Cannot execute: {exc}"
        r["evidence"] = None
        notes.append(f"{php_bin} -> {exc}")
        r["binary"] = php_bin
        r["detection_log"] = notes
        return r

    text = (out.stdout or "") + (out.stderr or "")
    if out.returncode != 0:
        notes.append(f"{php_bin} -> return code {out.returncode}")
    tokens = sorted(set(extract_php_tokens(text)))
    observations = None
    if not tokens:
        r = assess(_blank_parsed())
        r["detail"] = "PHP version token not found in the output of -v."
        notes.append(f"{php_bin} -> version not recognized")
    elif len(tokens) > 1:
        r = assess(_blank_parsed())
        r["detail"] = "Multiple/conflicting PHP tokens: " + ", ".join(tokens)
        notes.append(f"{php_bin} -> conflict {tokens}")
        observations = [{"binary": php_bin, "version_raw": t} for t in tokens]
    else:
        r = assess(split_version(tokens[0]))
        notes.append(f"{php_bin} -> PHP {tokens[0]}")

    if out.returncode != 0:
        r["verdict"] = UNDETERMINED
        r["detail"] = (
            f"The binary exited with code {out.returncode}. "
            "Any observed version is kept, "
            "but does not allow a reliable conclusion."
        )

    r["detection_method"] = "local"
    r["binary"] = php_bin
    r["evidence"] = (
        f"`{php_bin} -v` reports PHP {tokens[0]}"
        if len(tokens) == 1 else None
    )
    if observations is not None:
        r["observations"] = observations
    r["detection_log"] = notes
    return r


def detect_local(php_bin: str | None) -> dict:
    if php_bin:
        bins = [php_bin]
    else:
        bins = []
        seen = set()
        for name in LOCAL_CANDIDATES:
            resolved = shutil.which(name)
            if not resolved:
                continue
            real = os.path.realpath(resolved)
            if real in seen:
                continue
            seen.add(real)
            bins.append(resolved)

    entries = [_assess_binary(b) for b in bins]
    if not entries:
        overall = assess(_blank_parsed())
        overall["detail"] = "No PHP binary found in PATH."
    else:
        worst = max(entries, key=lambda e: _SEVERITY_RANK[e["verdict"]])
        overall = dict(worst)

    overall["detection_method"] = "local"
    overall["source"] = php_bin or "local PHP binaries (PATH)"
    overall["limitations"] = LIMITS_BY_SOURCE["local"]
    overall["inventory_note"] = LOCAL_INVENTORY_NOTE
    overall["entries"] = entries
    overall["detection_log"] = [n for e in entries for n in e.get("detection_log", [])] \
        or ["No PHP binary found in PATH."]
    return overall


# --------------------------------------------------------------------------- #
# Rendering — shared
# --------------------------------------------------------------------------- #
VERDICT_LABEL = {
    AFFECTED: "POTENTIALLY AFFECTED — declared version within an affected range",
    OUT_OF_RANGE: "OUTSIDE KNOWN AFFECTED RANGE — declared version outside the known affected ranges",
    UNDETERMINED: "UNDETERMINED — no reliable conclusion",
}


def _concise_reason(r: dict) -> str:
    if r["verdict"] == AFFECTED:
        if r.get("fixed_in"):
            return f"Announced version earlier than fix {r['fixed_in']}."
        return "Listed as affected (end of upstream support)."
    return r.get("detail", "")


def render_concise(target: str, r: dict) -> str:
    """Short default report. Three states, never a bare 'not vulnerable'."""
    ver = r.get("version_raw") or "not detected"
    lines = [f"Target: {_sanitize(target, 200)}", f"PHP: {_sanitize(ver, 60)}"]
    v = r["verdict"]
    if v == AFFECTED:
        lines.append("Potentially vulnerable: YES")
        lines.append(_sanitize(_concise_reason(r)))
        lines.append("Action: check vendor patches and update if necessary.")
    elif v == OUT_OF_RANGE:
        lines.append("In a known vulnerable range: NO")
        lines.append("The announced version reaches the fixed threshold for both CVEs.")
        lines.append("This result does not verify the runtime actually used by the site.")
    else:
        lines.append("Result: UNDETERMINED")
        lines.append(_sanitize(_concise_reason(r)))
        lines.append("Action: check the PHP package and web runtime internally.")

    entries = r.get("entries")
    if entries and len(entries) > 1:
        lines.append(f"({len(entries)} binaries scanned; use --verbose for per-binary detail)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Rendering — verbose
# --------------------------------------------------------------------------- #
def _assessment_lines(r: dict, indent: str = "") -> list:
    lines = []
    ver = r.get("version_raw") or "(not detected)"
    lines.append(f"{indent}PHP version  : {_sanitize(ver, 80)}")
    if r.get("version_suffix"):
        lines.append(f"{indent}  (upstream {_sanitize(str(r['upstream_version']), 40)}, "
                     f"suffix {_sanitize(repr(r['version_suffix']), 60)}, class {r.get('suffix_class')})")
    lines.append(f"{indent}Verdict      : {VERDICT_LABEL[r['verdict']]}")
    if r.get("evidence"):
        lines.append(f"{indent}Evidence     : {_sanitize(r['evidence'])}")
    lines.append(f"{indent}Upstream supp: {_sanitize(r['upstream_support_status'])} "
                 f"(as of {REFERENCE_DATA_UPDATED_AT})")
    lines.append(f"{indent}Vendor patch : {r['vendor_patch_status']}")
    if r.get("anomaly"):
        lines.append(f"{indent}Anomaly      : {_sanitize(r['anomaly'])}")
    lines.append(f"{indent}Detail       : {_sanitize(r['detail'])}")
    if r.get("support_note"):
        lines.append(f"{indent}Support note : {_sanitize(r['support_note'])}")
    if r.get("observations"):
        lines.append(f"{indent}Observations :")
        for o in r["observations"]:
            src = o.get("header") or o.get("binary") or "?"
            lines.append(f"{indent}  - {_sanitize(str(src), 80)} => "
                         f"{_sanitize(str(o.get('version_raw')), 60)}")
    if r["verdict"] == AFFECTED:
        lines.append(f"{indent}CVE severity : {CVE_SEVERITY_NOTE}")
    if r.get("fixed_in"):
        lines.append(f"{indent}Fixed in     : {r['fixed_in']}")
    return lines


def render_verbose(target: str, r: dict) -> str:
    sep = "=" * 70
    lines = [sep, "  php2shell scanner (CVE-2026-109618 + CVE-2026-109619)", sep]
    lines.append(f"Target       : {_sanitize(target, 200)}")
    lines.append(f"Method       : {r.get('detection_method')}")
    if r.get("requested_url"):
        lines.append(f"Requested URL: {_sanitize(r['requested_url'], 200)}")
    if r.get("final_url") and r.get("final_url") != r.get("requested_url"):
        lines.append(f"Final URL    : {_sanitize(str(r['final_url']), 200)}")
    if r.get("blocked_redirect_target"):
        lines.append(f"Blocked redir: {_sanitize(str(r['blocked_redirect_target']), 200)} "
                     f"({r.get('redirect_block_kind')}; not contacted)")

    entries = r.get("entries")
    if entries is not None and len(entries) > 0:
        lines.append(f"Binaries analyzed: {len(entries)}")
        for e in entries:
            lines.append("-" * 70)
            lines.append(f"  Binary       : {_sanitize(str(e.get('binary')), 200)}")
            lines.extend(_assessment_lines(e, indent="  "))
        lines.append("-" * 70)
        lines.append(f"Overall verdict: {VERDICT_LABEL[r['verdict']]}")
        lines.append("  (aggregate: an affected or undetermined binary is never "
                     "masked by a clean result)")
    else:
        lines.extend(_assessment_lines(r))

    if r.get("inventory_note"):
        lines.append(f"Inventory    : {r['inventory_note']}")
    if r.get("limitations"):
        lines.append(f"Limits       : {r['limitations']}")

    if r["verdict"] == AFFECTED:
        lines.append("")
        lines.append("Verification after update:")
        for ln in VERIFICATION_STEPS.splitlines():
            lines.append("  " + ln)
        lines.append("")
        for ln in WORKAROUNDS.splitlines():
            lines.append("  " + ln)

    lines.append("")
    lines.append(f"Reference data as of {REFERENCE_DATA_UPDATED_AT} "
                 f"(tool {TOOL_VERSION}, schema {SCHEMA_VERSION})")
    lines.append("Reference advisories (keep up to date):")
    for u in ADVISORY_REFERENCES:
        lines.append(f"  - {u}")

    log = r.get("detection_log")
    if log:
        lines.append("")
        lines.append("Detection log:")
        for n in log:
            lines.append(f"  - {_sanitize(n)}")
    lines.append(sep)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Rendering — JSON
# --------------------------------------------------------------------------- #
def _json_payload(target: str, r: dict) -> dict:
    def entry_view(e):
        view = {
            "binary": e.get("binary"),
            "version_raw": e.get("version_raw"),
            "upstream_version": e.get("upstream_version"),
            "version_suffix": e.get("version_suffix"),
            "suffix_class": e.get("suffix_class"),
            "verdict": e["verdict"],
            "upstream_support_status": e["upstream_support_status"],
            "vendor_patch_status": e["vendor_patch_status"],
            "fixed_in": e.get("fixed_in"),
            "evidence": e.get("evidence"),
            "detail": e["detail"],
        }
        if e.get("observations"):
            view["observations"] = e["observations"]
        return view

    payload = {
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "reference_data_updated_at": REFERENCE_DATA_UPDATED_AT,
        "detection_method": r.get("detection_method"),
        "target": target,
        "version_raw": r.get("version_raw"),
        "upstream_version": r.get("upstream_version"),
        "version_suffix": r.get("version_suffix"),
        "suffix_class": r.get("suffix_class"),
        "verdict": r["verdict"],
        "upstream_support_status": r["upstream_support_status"],
        "vendor_patch_status": r["vendor_patch_status"],
        "source": r.get("source"),
        "evidence": r.get("evidence"),
        "fixed_in": r.get("fixed_in"),
        "anomaly": r.get("anomaly"),
        "detail": r["detail"],
        "support_note": r.get("support_note"),
        "limitations": r.get("limitations"),
        "cve_severity_note": CVE_SEVERITY_NOTE,
        "cves_searched": list(CVES_SEARCHED),
        "advisory_references": list(ADVISORY_REFERENCES),
        "workarounds_note": WORKAROUNDS if r["verdict"] == AFFECTED else None,
        "verification_after_update": VERIFICATION_STEPS if r["verdict"] == AFFECTED else None,
        "detection_log": r.get("detection_log"),
    }
    if r.get("observations") is not None:
        payload["observations"] = r["observations"]
    if r.get("redirect_block_kind") is not None:
        payload["redirect_block_kind"] = r["redirect_block_kind"]
    if r.get("blocked_redirect_target") is not None:
        payload["blocked_redirect_target"] = r["blocked_redirect_target"]
    if r.get("inventory_note") is not None:
        payload["inventory_note"] = r["inventory_note"]
    if r.get("requested_url") is not None:
        payload["requested_url"] = r.get("requested_url")
        payload["final_url"] = r.get("final_url")
    if r.get("entries") is not None:
        payload["binaries"] = [entry_view(e) for e in r["entries"]]
    return payload


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _positive_finite(value: str) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("timeout must be a number")
    if not math.isfinite(f) or f <= 0:
        raise argparse.ArgumentTypeError("timeout must be strictly positive and finite")
    return f


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Non-exploiting evaluator of declared PHP versions for the "
        "php2shell RCEs (CVE-2026-109618 + CVE-2026-109619). Measures an exposure "
        "level from a declared version; collects no configuration and runs no "
        "attack. No detection or any doubt yields UNDETERMINED, never 'not "
        "vulnerable'.",
        epilog="Use only on systems you own or are authorized to test. Version "
        "ranges must be kept up to date with the referenced official advisories.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--local", action="store_true",
                       help="Scan PATH for PHP binaries with known names "
                            "(partial inventory) and evaluate each.")
    group.add_argument("--php-bin", metavar="PATH",
                       help="Query a specific PHP binary path or name "
                            "(e.g. /usr/sbin/php-fpm8.3).")
    group.add_argument("--version", metavar="X.Y.Z",
                       help="Evaluate a STRICT version string (no execution).")
    group.add_argument("--url", metavar="URL",
                       help="Fingerprint via HTTP headers (origin-locked).")
    parser.add_argument("--timeout", type=_positive_finite, default=10.0,
                        help="Network timeout (s) for --url (default 10, > 0).")
    parser.add_argument("--verbose", action="store_true",
                        help="Detailed report (evidence, limits, binaries, "
                             "redirects, recommendations).")
    parser.add_argument("--json", action="store_true",
                        help="Machine-readable JSON output.")
    args = parser.parse_args(argv)

    # Select by option presence (not by truthiness): --version '' does not fall
    # back to local detection.
    if args.version is not None:
        target = f"supplied version: {args.version!r}"
        result = detect_manual(args.version)
    elif args.url is not None:
        target = args.url
        result = detect_remote(args.url, args.timeout)
    elif args.php_bin is not None:
        target = args.php_bin
        result = detect_local(args.php_bin)
    else:  # --local
        target = "local PHP binaries (PATH)"
        result = detect_local(None)

    if args.json:
        print(json.dumps(_json_payload(target, result), ensure_ascii=False, indent=2))
    elif args.verbose:
        print(render_verbose(target, result))
    else:
        print(render_concise(target, result))

    return EXIT_CODE[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
