"""
scanner_core.py — ThreatMap Infra full scanner suite.

Speed design
------------
Evasion delays exist to avoid tripping IDS/WAF on production targets.
But they were wildly over-tuned — 5–10s per tool call stacks to 7+ minutes
on a simple scan. Revised delays:

  Balanced   : 0.5–1.5s between tool launches (reasonable, not sluggish)
  Aggressive : 0.1–0.5s (you explicitly chose loud — minimal throttling)

Web tools (nikto, gobuster, curl, sslscan) run in parallel threads per host,
so their delays don't stack sequentially.

The random User-Agent and inter-tool pauses are preserved — just sane.
"""

import logging
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
import json
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

logger = logging.getLogger("threatmap.scanner")

MODE_BALANCED   = "balanced"
MODE_AGGRESSIVE = "aggressive"

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------

class Target:
    def __init__(self, raw_input: str):
        self.raw    = raw_input.strip()
        clean       = self.raw.replace("https://", "").replace("http://", "")
        self.domain = clean.split("/")[0].split("?")[0]
        self.url    = f"https://{self.domain}"


# ---------------------------------------------------------------------------
# Tool resolver
# ---------------------------------------------------------------------------

class ToolResolver:
    @staticmethod
    def get(name: str, validate_args: list | None = None,
            expected: str | None = None) -> str | None:
        override = os.environ.get(f"{name.upper().replace('-','_')}_PATH")
        if override and os.path.isfile(override):
            return override
        path = shutil.which(name)
        if not path:
            return None
        if validate_args and expected:
            try:
                res = subprocess.run([path] + validate_args, capture_output=True,
                                     text=True, timeout=6)
                if expected.lower() not in (res.stdout + res.stderr).lower():
                    return None
            except Exception:
                return None
        return path


# ---------------------------------------------------------------------------
# Evasion helpers — sane delays
# ---------------------------------------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:125.0) Gecko/20100101 Firefox/125.0",
]

def _random_ua() -> str:
    return random.choice(USER_AGENTS)

def _delay(mode: str) -> None:
    """
    Balanced  : 0.5–1.5s   — polite but not painful
    Aggressive: 0.1–0.5s   — minimal; user explicitly chose loud
    No delay at all for OSINT tools (whois, dig, nslookup) — they're read-only
    """
    if mode == MODE_AGGRESSIVE:
        time.sleep(random.uniform(0.1, 0.5))
    else:
        time.sleep(random.uniform(0.5, 1.5))


# ---------------------------------------------------------------------------
# ScannerKit
# ---------------------------------------------------------------------------

class ScannerKit:

    # ── Subdomain discovery ────────────────────────────────────────────

    @staticmethod
    def run_subfinder(target: Target) -> list[str]:
        logger.info("[subfinder] Starting on %s", target.domain)
        bin_path = ToolResolver.get("subfinder", ["-version"], "subfinder")
        if not bin_path:
            return []
        try:
            subprocess.run(
                [bin_path, "-d", target.domain, "-silent",
                 "-o", "reports/subdomains.txt"],
                stderr=subprocess.DEVNULL, timeout=120,
            )
            subs = [s.strip() for s in
                    Path("reports/subdomains.txt").read_text().splitlines()
                    if s.strip()]
            logger.info("[subfinder] Found %d subdomains", len(subs))
            return subs
        except Exception as exc:
            logger.warning("[subfinder] Failed: %s", exc)
            return []

    @staticmethod
    def run_assetfinder(target: Target) -> list[str]:
        logger.info("[assetfinder] Starting on %s", target.domain)
        bin_path = ToolResolver.get("assetfinder")
        if not bin_path:
            logger.info("[assetfinder] Not installed — skipping")
            return []
        try:
            result = subprocess.run(
                [bin_path, "--subs-only", target.domain],
                capture_output=True, text=True, timeout=60,
            )
            subs = [l.strip() for l in result.stdout.splitlines()
                    if l.strip() and target.domain in l]
            logger.info("[assetfinder] Found %d subdomains", len(subs))
            return subs
        except Exception as exc:
            logger.warning("[assetfinder] Failed: %s", exc)
            return []

    @staticmethod
    def run_httpx(subs_file: str = "reports/subdomains.txt") -> list[str]:
        logger.info("[httpx] Filtering live hosts...")
        bin_path = ToolResolver.get("httpx", ["-version"], "httpx")
        if not bin_path or not Path(subs_file).exists():
            return []
        try:
            subprocess.run(
                [bin_path, "-l", subs_file, "-silent",
                 "-o", "reports/live_hosts.txt"],
                stderr=subprocess.DEVNULL, timeout=120,
            )
            hosts = [l.strip() for l in
                     Path("reports/live_hosts.txt").read_text().splitlines()
                     if l.strip()]
            logger.info("[httpx] %d live hosts", len(hosts))
            return hosts
        except Exception as exc:
            logger.warning("[httpx] Failed: %s", exc)
            return []

    # ── OSINT / DNS — no delays needed (read-only, no scanning) ───────

    @staticmethod
    def run_whois(target: Target) -> None:
        logger.info("[whois] WHOIS lookup for %s", target.domain)
        out = f"reports/whois_{target.domain}.txt"
        try:
            with open(out, "w") as f:
                subprocess.run(["whois", target.domain],
                               stdout=f, stderr=subprocess.DEVNULL, timeout=20)
            logger.info("[whois] Done.")
        except Exception as exc:
            logger.warning("[whois] %s", exc)

    @staticmethod
    def run_dig(target: Target) -> None:
        logger.info("[dig] DNS enumeration for %s", target.domain)
        out = f"reports/dig_{target.domain}.txt"
        try:
            with open(out, "w") as f:
                for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
                    f.write(f"\n=== {rtype} ===\n")
                    r = subprocess.run(["dig", target.domain, rtype, "+short"],
                                       capture_output=True, text=True, timeout=10)
                    f.write(r.stdout or "(none)\n")
            logger.info("[dig] DNS records captured (A, AAAA, MX, NS, TXT, SOA)")
        except Exception as exc:
            logger.warning("[dig] %s", exc)

    @staticmethod
    def run_nslookup(target: Target) -> None:
        logger.info("[nslookup] NS lookup for %s", target.domain)
        out = f"reports/nslookup_{target.domain}.txt"
        try:
            with open(out, "w") as f:
                r = subprocess.run(["nslookup", target.domain],
                                   capture_output=True, text=True, timeout=10)
                f.write(r.stdout)
            logger.info("[nslookup] Complete.")
        except Exception as exc:
            logger.warning("[nslookup] %s", exc)

    # ── Port scanning ──────────────────────────────────────────────────

    @staticmethod
    def run_nmap(target: Target, mode: str = MODE_BALANCED) -> list[dict]:
        _delay(mode)
        logger.info("[nmap] Scanning %s (mode: %s)", target.domain, mode)
        out = f"reports/nmap_{target.domain}.xml"

        if mode == MODE_AGGRESSIVE:
            cmd = ["nmap", "-sV", "-sC", "-A", "-Pn", "-p-",
                   "--min-rate", "2000", "--max-retries", "1",
                   "-T4", "-oX", out, target.domain]
            fallback = ["nmap", "-sV", "-sC", "-Pn", "--top-ports", "5000",
                        "-T4", "-oX", out, target.domain]
            timeout = 900
        else:
            cmd = ["nmap", "-sV", "-sC", "-Pn", "--top-ports", "1000",
                   "-T4", "--max-retries", "1", "-oX", out, target.domain]
            fallback = ["nmap", "-sS", "-Pn", "--top-ports", "200",
                        "-T3", "-oX", out, target.domain]
            timeout = 300

        for attempt, c in enumerate([cmd, fallback], 1):
            try:
                subprocess.run(c, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=timeout)
                break
            except subprocess.TimeoutExpired:
                if attempt == 1:
                    logger.warning("[nmap] Primary timed out, running fallback...")

        results = []
        try:
            tree = ET.parse(out)
            for port in tree.getroot().findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc   = port.find("service")
                ver_parts = [
                    svc.get(a, "") for a in ["product", "version", "extrainfo"]
                    if svc is not None and svc.get(a)
                ]
                results.append({
                    "port":     port.get("portid"),
                    "protocol": port.get("protocol", "tcp"),
                    "state":    "open",
                    "service":  svc.get("name", "unknown") if svc is not None else "unknown",
                    "version":  " ".join(ver_parts),
                    "cpe":      [c.text for c in port.findall(".//cpe") if c.text],
                })
        except Exception as exc:
            logger.warning("[nmap] XML parse error: %s", exc)

        logger.info("[nmap] Open ports: %s",
                    [r["port"] for r in results] or "none/filtered")
        return results

    # ── Technology & WAF ──────────────────────────────────────────────

    @staticmethod
    def run_whatweb(target: Target, mode: str = MODE_BALANCED) -> None:
        _delay(mode)
        logger.info("[whatweb] Fingerprinting %s", target.url)
        out = f"reports/whatweb_{target.domain}.json"
        try:
            subprocess.run(
                ["whatweb", "-v", "--user-agent", _random_ua(),
                 f"--log-json={out}", target.url],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60,
            )
            try:
                data = json.loads(Path(out).read_text())
                tech = list(set(
                    p for e in data if "plugins" in e
                    for p in e["plugins"].keys()
                ))
                logger.info("[whatweb] Technologies: %s",
                            ", ".join(tech[:6]) or "none detected")
            except Exception:
                pass
        except Exception as exc:
            logger.warning("[whatweb] %s", exc)

    @staticmethod
    def run_wafw00f(target: Target, mode: str = MODE_BALANCED) -> None:
        _delay(mode)
        logger.info("[wafw00f] WAF check on %s", target.url)
        bin_path = ToolResolver.get("wafw00f") or ToolResolver.get("wafwoof")
        if not bin_path:
            logger.info("[wafw00f] Not installed — skipping (pip install wafw00f)")
            return
        out = f"reports/wafw00f_{target.domain}.txt"
        try:
            with open(out, "w") as f:
                subprocess.run([bin_path, "-a", target.url],
                               stdout=f, stderr=subprocess.DEVNULL, timeout=30)
            content = Path(out).read_text()
            if any(k in content.lower() for k in ["is behind", "detected"]):
                logger.info("[wafw00f] WAF DETECTED — see %s", out)
            else:
                logger.info("[wafw00f] No WAF detected.")
        except Exception as exc:
            logger.warning("[wafw00f] %s", exc)

    # ── Web vulnerability tools ────────────────────────────────────────

    @staticmethod
    def run_nikto(target: Target, mode: str = MODE_BALANCED) -> None:
        _delay(mode)
        logger.info("[nikto] Web scan on %s", target.url)
        out     = f"reports/nikto_{target.domain}.txt"
        maxtime = "5m" if mode == MODE_AGGRESSIVE else "3m"
        try:
            subprocess.run(
                ["nikto", "-h", target.url, "-useragent", _random_ua(),
                 "-output", out, "-maxtime", maxtime, "-nointeractive"],
                stdout=subprocess.DEVNULL, timeout=360,
            )
            logger.info("[nikto] Web scan complete.")
        except subprocess.TimeoutExpired:
            logger.warning("[nikto] Timed out (partial results kept).")
        except Exception as exc:
            logger.warning("[nikto] %s", exc)

    @staticmethod
    def run_gobuster(target: Target, mode: str = MODE_BALANCED) -> None:
        _delay(mode)
        logger.info("[gobuster] Directory enumeration on %s", target.url)
        out = f"reports/gobuster_{target.domain}.txt"

        wordlists = (
            [
                "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "/usr/share/wordlists/dirb/big.txt",
            ]
            if mode == MODE_AGGRESSIVE else
            [
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
            ]
        )
        wordlist = next((w for w in wordlists if Path(w).exists()), None)
        if not wordlist:
            logger.warning("[gobuster] No wordlist found — skipping "
                           "(apt install seclists)")
            return

        threads = "80" if mode == MODE_AGGRESSIVE else "50"
        try:
            subprocess.run(
                ["gobuster", "dir", "-u", target.url, "-w", wordlist,
                 "-a", _random_ua(), "-o", out,
                 "-b", "404,301,302", "-t", threads,
                 "--timeout", "8s", "-q"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=300,
            )
            try:
                count = len([l for l in Path(out).read_text().splitlines() if l])
                logger.info("[gobuster] Found %d paths.", count)
            except FileNotFoundError:
                pass
        except Exception as exc:
            logger.warning("[gobuster] %s", exc)

    @staticmethod
    def run_sslscan(target: Target, mode: str = MODE_BALANCED) -> None:
        _delay(mode)
        logger.info("[sslscan] TLS analysis on %s", target.domain)
        out = f"reports/sslscan_{target.domain}.txt"
        try:
            with open(out, "w") as f:
                subprocess.run(["sslscan", "--no-colour", target.domain],
                               stdout=f, stderr=subprocess.DEVNULL, timeout=60)
            logger.info("[sslscan] TLS data captured.")
        except subprocess.TimeoutExpired:
            logger.warning("[sslscan] Timed out.")
        except Exception as exc:
            logger.warning("[sslscan] %s", exc)

    @staticmethod
    def run_curl_recon(target: Target, mode: str = MODE_BALANCED) -> None:
        _delay(mode)
        logger.info("[curl] HTTP headers on %s", target.url)
        out = f"reports/curl_headers_{target.domain}.txt"
        try:
            with open(out, "w") as f:
                subprocess.run(
                    ["curl", "-s", "-I", "-L", "--max-redirs", "5",
                     "-A", _random_ua(), "--connect-timeout", "8",
                     "--max-time", "15", target.url],
                    stdout=f, stderr=subprocess.DEVNULL, timeout=20,
                )
            logger.info("[curl] HTTP headers captured.")
        except Exception as exc:
            logger.warning("[curl] %s", exc)

    @staticmethod
    def run_nuclei(target: Target, mode: str = MODE_BALANCED) -> None:
        logger.info("[nuclei] Template scan on %s (mode: %s)", target.url, mode)
        bin_path = ToolResolver.get("nuclei", ["-version"], "nuclei")
        if not bin_path:
            logger.info("[nuclei] Not installed — skipping "
                        "(go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)")
            return
        out = f"reports/nuclei_{target.domain}.txt"
        if mode == MODE_AGGRESSIVE:
            cmd = [bin_path, "-u", target.url, "-o", out, "-silent",
                   "-timeout", "10", "-rate-limit", "150",
                   "-bulk-size", "30", "-c", "30"]
            timeout = 900
        else:
            # Balanced — critical/high/medium only, fast tags
            cmd = [bin_path, "-u", target.url, "-o", out, "-silent",
                   "-severity", "critical,high,medium",
                   "-tags", "cve,exposure,misconfig,default-login,takeover",
                   "-timeout", "8", "-rate-limit", "80",
                   "-bulk-size", "20", "-c", "20"]
            timeout = 300
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout)
            try:
                findings = [l for l in Path(out).read_text().splitlines() if l.strip()]
                logger.info("[nuclei] %d findings.", len(findings))
            except FileNotFoundError:
                logger.info("[nuclei] No findings.")
        except subprocess.TimeoutExpired:
            logger.warning("[nuclei] Timed out (partial results kept).")
        except Exception as exc:
            logger.warning("[nuclei] %s", exc)


# ---------------------------------------------------------------------------
# ParallelOrchestrator
# ---------------------------------------------------------------------------

class ParallelOrchestrator:
    """
    Runs the full scan suite across multiple hosts.

    Per-host: OSINT tools run first (no delay, fast).
    Then nmap. Then web tools all run in parallel threads — their individual
    delays don't stack sequentially.
    Nuclei runs after ports are known (needs to know if web is up).
    """

    MAX_WORKERS = {MODE_BALANCED: 4, MODE_AGGRESSIVE: 6}

    def __init__(self, mode: str = MODE_BALANCED):
        self.mode        = mode
        self.max_workers = self.MAX_WORKERS.get(mode, 4)
        self.results: dict[str, dict] = {}
        logger.info("Orchestrator: mode=%s  workers=%d",
                    self.mode, self.max_workers)

    def run_scan_suite(self, hosts: list[str]) -> dict[str, dict]:
        logger.info("Scanning %d host(s) in parallel.", len(hosts))
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            fmap = {ex.submit(self._scan_single_host, h): h for h in hosts}
            for future in as_completed(fmap):
                host = fmap[future]
                try:
                    self.results[host] = future.result()
                except Exception as exc:
                    logger.error("Scan failed %s: %s", host, exc)
                    self.results[host] = {"host": host, "error": str(exc)}
        return self.results

    def _scan_single_host(self, host: str) -> dict:
        logger.info("━━━ Scanning: %s [%s] ━━━", host, self.mode)
        target = Target(host)
        result = {"host": host, "nmap": [], "open_ports": [], "error": None}

        # ── OSINT (no delays — purely read-only lookups) ───────────────
        with ThreadPoolExecutor(max_workers=3) as osint:
            osint.submit(ScannerKit.run_whois,    target).result()
            osint.submit(ScannerKit.run_dig,      target).result()
            osint.submit(ScannerKit.run_nslookup, target).result()

        # ── Technology fingerprint + WAF (parallel, small delay each) ──
        with ThreadPoolExecutor(max_workers=2) as fp:
            f_ww  = fp.submit(ScannerKit.run_whatweb, target, self.mode)
            f_waf = fp.submit(ScannerKit.run_wafw00f, target, self.mode)
            f_ww.result()
            f_waf.result()

        # ── Port scan ──────────────────────────────────────────────────
        nmap_results        = ScannerKit.run_nmap(target, mode=self.mode)
        result["nmap"]      = nmap_results
        open_ports          = {r["port"] for r in nmap_results}
        result["open_ports"] = list(open_ports)

        # ── Web tools — all run in parallel ───────────────────────────
        has_web = bool(
            open_ports & {"80", "443", "8080", "8443", "8000", "8888"}
        ) or host.startswith("http")

        if has_web:
            with ThreadPoolExecutor(max_workers=4) as web:
                futures = {
                    web.submit(ScannerKit.run_nikto,    target, self.mode): "nikto",
                    web.submit(ScannerKit.run_curl_recon, target, self.mode): "curl",
                    web.submit(ScannerKit.run_gobuster, target, self.mode): "gobuster",
                }
                if "443" in open_ports or host.startswith("https"):
                    futures[web.submit(ScannerKit.run_sslscan, target, self.mode)] = "sslscan"
                for f in as_completed(futures):
                    tool = futures[f]
                    try:
                        f.result()
                    except Exception as exc:
                        logger.warning("[%s] Error: %s", tool, exc)

        # ── Nuclei (template-based CVEs — after we know what's running) ─
        if has_web or open_ports:
            ScannerKit.run_nuclei(target, mode=self.mode)

        logger.info("━━━ Done: %s  ports=%s ━━━",
                    host, result["open_ports"] or "none")
        return result
