"""
evidence_collector.py — Reliable web evidence capture for ThreatMap reports.

Design principle
----------------
Playwright / browser automation is fragile in VMs, headless environments, and
during pentests where the target may return unusual content.  This module uses
a two-layer approach:

Layer 1 (always runs): requests-based HTTP probe
    → HTTP status code, response time, page <title>, security headers audit,
      server banner, redirect chain.  Stored as structured JSON per host.
    → Works 100% reliably, zero browser dependency, never hangs.

Layer 2 (optional): EyeWitness screenshot
    → Only attempted if the `eyewitness` binary / EyeWitness.py is found.
    → Graceful skip if not installed — Layer 1 evidence always covers the gap.
"""

import json
import os
import re
import sys
import shutil
import subprocess
import platform
import time
import threading
from html.parser import HTMLParser
from pathlib import Path
from typing import TYPE_CHECKING

import logging

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

logger = logging.getLogger("threatmap.evidence")

if TYPE_CHECKING:
    from db_manager import DBManager


# ---------------------------------------------------------------------------
# Tiny HTML title extractor (no external deps)
# ---------------------------------------------------------------------------

class _TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title: str = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip()


def _extract_title(html: str) -> str:
    p = _TitleParser()
    try:
        p.feed(html[:8192])
    except Exception:
        pass
    return p.title[:200] if p.title else ""


# ---------------------------------------------------------------------------
# Security header checklist (OWASP recommended)
# ---------------------------------------------------------------------------

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

_PROBE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/115.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
    "Accept-Language": "en-US,en;q=0.9",
}


# ---------------------------------------------------------------------------
# EyeWitness HTML report parser
# ---------------------------------------------------------------------------

class _EyeWitnessReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result: dict[str, str] = {}
        self._current_url: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple]) -> None:
        attr_dict = dict(attrs)
        if tag == "div":
            div_id = attr_dict.get("id", "")
            if div_id.startswith(("http://", "https://")):
                self._current_url = div_id
        if tag == "img" and self._current_url:
            src = attr_dict.get("src", "")
            if src.startswith("screens/") and src.endswith(".png"):
                self.result[self._current_url] = src
                self._current_url = None


# ---------------------------------------------------------------------------
# EvidenceCollector
# ---------------------------------------------------------------------------

class EvidenceCollector:
    """
    Collects structured HTTP evidence for every discovered host.
    Layer 1 (HTTP probe) always runs.  Layer 2 (EyeWitness) is optional.
    """

    _EW_SEARCH_PATHS = [
        "/usr/bin/eyewitness",
        "/usr/local/bin/eyewitness",
        os.path.expanduser("~/EyeWitness/EyeWitness.py"),
        os.path.expanduser("~/tools/EyeWitness/EyeWitness.py"),
        "/opt/EyeWitness/EyeWitness.py",
        "/opt/tools/EyeWitness/EyeWitness.py",
    ]

    def __init__(self, db: "DBManager", scan_id: int):
        self.db = db
        self.scan_id = scan_id
        self._ew_bin: str | None = self._find_eyewitness()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture_screenshots(
        self,
        hosts: list[str],
        output_dir: str,
        host_id_map: dict[str, int] | None = None,
    ) -> dict[str, dict]:
        """
        Probe all hosts (Layer 1) and optionally screenshot them (Layer 2).
        Returns {url: evidence_dict}.
        """
        if not hosts:
            return {}

        host_id_map = host_id_map or {}
        os.makedirs(output_dir, exist_ok=True)
        all_evidence: dict[str, dict] = {}

        # ── Layer 1: HTTP probe ────────────────────────────────────────
        if not _REQUESTS_OK:
            logger.warning("[!] 'requests' not installed — run: pip install requests")
        else:
            logger.info(f"[+] HTTP Evidence: probing {len(hosts)} host(s)...")
            lock = threading.Lock()

            def _probe(url: str) -> None:
                evidence = self._http_probe(url)
                with lock:
                    all_evidence[url] = evidence

            threads = [
                threading.Thread(target=_probe, args=(h,), daemon=True)
                for h in hosts
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)

            for url, evidence in all_evidence.items():
                host_id = host_id_map.get(url)
                evidence_path = self._save_evidence_json(url, evidence, output_dir)
                if host_id:
                    self.db.upsert_screenshot(
                        host_id=host_id,
                        url=url,
                        screenshot_path=evidence_path,
                        eyewitness_dir=None,
                        http_status=evidence.get("status_code"),
                        page_title=evidence.get("title"),
                    )

            ok = sum(1 for e in all_evidence.values() if e.get("status_code"))
            logger.info(f"    ↳ [Summary] HTTP evidence captured for {ok}/{len(hosts)} hosts.")

        # ── Layer 2: EyeWitness (optional) ────────────────────────────
        if self._ew_bin:
            logger.info(f"[+] EyeWitness: capturing screenshots...")
            ew_dir = str(Path(output_dir) / "eyewitness")
            screenshot_map = self._run_eyewitness_and_parse(hosts, ew_dir)

            for url, png_path in screenshot_map.items():
                host_id = host_id_map.get(url)
                if host_id and png_path:
                    with self.db._conn() as conn:
                        conn.execute(
                            "UPDATE screenshots SET screenshot_path=?, eyewitness_dir=? "
                            "WHERE host_id=? AND url=?",
                            (png_path, ew_dir, host_id, url),
                        )
                    if url in all_evidence:
                        all_evidence[url]["screenshot_path"] = png_path

            got = sum(1 for v in screenshot_map.values() if v)
            logger.info(f"    ↳ [Summary] EyeWitness: {got}/{len(hosts)} screenshots captured.")
        else:
            logger.info(
                "[*] EyeWitness not found — HTTP-only evidence mode.\n"
                "    Optional: pip install eyewitness  "
                "or  git clone https://github.com/FortyNorthSecurity/EyeWitness"
            )

        return all_evidence

    def record_terminal_session(self, scan_cmd: list[str], log_path: str) -> bool:
        """Record a terminal session with script(1). Returns True on success."""
        if not shutil.which("script"):
            logger.warning("[!] 'script' binary not found — skipping terminal recording.")
            return False

        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        is_macos = platform.system() == "Darwin"
        cmd = (
            ["script", "-q", log_path] + scan_cmd
            if is_macos
            else ["script", "-q", "-c", " ".join(scan_cmd), log_path]
        )
        try:
            subprocess.run(cmd, timeout=600)
        except (subprocess.TimeoutExpired, Exception) as exc:
            logger.warning(f"[-] Terminal recording failed: {exc}")
            return False

        clean_path = log_path + ".clean.txt"
        self._scrub_typescript(log_path, clean_path)
        self.db.insert_terminal_log(self.scan_id, " ".join(scan_cmd), clean_path)
        logger.info(f"    ↳ Terminal session → {clean_path}")
        return True

    # ------------------------------------------------------------------
    # Layer 1: HTTP probe
    # ------------------------------------------------------------------

    @staticmethod
    def _http_probe(url: str) -> dict:
        result: dict = {
            "url": url,
            "status_code": None,
            "title": "",
            "server": "",
            "response_time_ms": None,
            "redirect_chain": [],
            "security_headers": {},
            "missing_security_headers": [],
            "error": None,
        }
        try:
            t0 = time.perf_counter()
            resp = requests.get(
                url,
                headers=_PROBE_HEADERS,
                timeout=12,
                verify=False,
                allow_redirects=True,
            )
            elapsed = int((time.perf_counter() - t0) * 1000)
            result["status_code"] = resp.status_code
            result["response_time_ms"] = elapsed
            result["server"] = resp.headers.get("Server", "")
            result["title"] = _extract_title(resp.text)
            result["redirect_chain"] = [r.url for r in resp.history]

            for h in SECURITY_HEADERS:
                value = resp.headers.get(h)
                result["security_headers"][h] = value
                if value is None:
                    result["missing_security_headers"].append(h)

        except requests.exceptions.ConnectionError:
            result["error"] = "Connection refused / host unreachable"
        except requests.exceptions.Timeout:
            result["error"] = "Request timed out (12s)"
        except Exception as exc:
            result["error"] = str(exc)

        return result

    @staticmethod
    def _save_evidence_json(url: str, evidence: dict, output_dir: str) -> str:
        safe = (
            url.replace("https://", "")
               .replace("http://", "")
               .replace("/", "_")
               .replace(":", "_")
        )
        path = os.path.join(output_dir, f"evidence_{safe}.json")
        try:
            Path(path).write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        except Exception:
            pass
        return path

    # ------------------------------------------------------------------
    # Layer 2: EyeWitness
    # ------------------------------------------------------------------

    def _run_eyewitness_and_parse(
        self, hosts: list[str], ew_dir: str
    ) -> dict[str, str | None]:
        hosts_file = Path(ew_dir).parent / "ew_targets.txt"
        hosts_file.parent.mkdir(parents=True, exist_ok=True)
        hosts_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

        base = (
            [sys.executable, self._ew_bin]
            if self._ew_bin.endswith(".py")
            else [self._ew_bin]
        )
        cmd = base + [
            "--web", "-f", str(hosts_file),
            "--no-prompt", "-d", ew_dir,
            "--timeout", "10", "--jitter", "2",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            logger.warning("[-] EyeWitness timed out — partial results may exist.")
        except Exception as exc:
            logger.warning(f"[-] EyeWitness error: {exc}")
            return {}

        return self._parse_eyewitness_output(ew_dir, hosts)

    def _parse_eyewitness_output(
        self, ew_dir: str, requested_hosts: list[str]
    ) -> dict[str, str | None]:
        result: dict[str, str | None] = {}
        report_html = Path(ew_dir) / "report.html"
        screens_dir = Path(ew_dir) / "screens"

        if report_html.exists():
            try:
                parser = _EyeWitnessReportParser()
                parser.feed(report_html.read_text(encoding="utf-8", errors="replace"))
                for url, rel in parser.result.items():
                    abs_path = str(Path(ew_dir) / rel)
                    if os.path.isfile(abs_path):
                        result[url] = abs_path
            except Exception:
                pass

        if screens_dir.is_dir():
            pngs = list(screens_dir.glob("*.png"))
            for url in requested_hosts:
                if url not in result:
                    matched = self._match_by_filename(url, pngs)
                    result[url] = str(matched) if matched else None

        return result

    @staticmethod
    def _match_by_filename(url: str, pngs: list[Path]) -> Path | None:
        needle = (
            url.replace("://", ".")
               .replace(":", ".")
               .replace("/", "_")
               .rstrip("_")
               .lower()
        )
        hostname = url.split("://")[-1].split("/")[0].split(":")[0].lower()
        for png in pngs:
            stem = png.stem.lower()
            if stem == needle or hostname in stem:
                return png
        return None

    def _find_eyewitness(self) -> str | None:
        env = os.environ.get("EYEWITNESS_PATH")
        if env and os.path.isfile(env):
            return env
        found = shutil.which("eyewitness")
        if found:
            return found
        for candidate in self._EW_SEARCH_PATHS:
            if os.path.isfile(candidate):
                return candidate
        return None

    # ------------------------------------------------------------------
    # ANSI scrubber
    # ------------------------------------------------------------------

    _ANSI_RE = re.compile(
        r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
        r"|\r|\x07|\x08+"
    )

    @classmethod
    def _scrub_typescript(cls, src: str, dst: str) -> None:
        try:
            raw = Path(src).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return
        lines = raw.splitlines()
        if lines and lines[0].startswith("Script started"):
            lines = lines[1:]
        if lines and lines[-1].startswith("Script done"):
            lines = lines[:-1]
        Path(dst).write_text(
            cls._ANSI_RE.sub("", "\n".join(lines)), encoding="utf-8"
        )
