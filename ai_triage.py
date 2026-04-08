"""
ai_triage.py — AI-assisted vulnerability triage for ThreatMap Infra.

Triage Tiers (tried in order, first available wins)
─────────────────────────────────────────────────────
Tier 0  Rule-based engine          — always active, zero dependencies
Tier 1  Local SLM (default AI)     — llama-cpp-python + GGUF model
         No API key. No Ollama. No internet at inference time.
         pip install llama-cpp-python huggingface_hub
         python3 setup_slm.py   (one-time ~1 GB download)
Tier 2  Cloud LLM (optional)       — Groq / OpenAI / Gemini
         export THREATMAP_LLM_PROVIDER=groq
         export THREATMAP_LLM_API_KEY=gsk_...

The AI generates FIVE fields matching the professional report format:
  observation_name    — short title  (e.g. "SSH Remote Access Exposed")
  detailed_observation — what was specifically found (port, version, data)
  impacted_module     — system category (e.g. "Remote Access", "Web Server")
  risk_impact         — 1-sentence business risk
  recommendation      — specific prioritised fix steps
"""

import json
import logging
import os
import re
import threading
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

logger = logging.getLogger("threatmap.triage")

if TYPE_CHECKING:
    from db_manager import DBManager

try:
    import requests as _requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False


# ---------------------------------------------------------------------------
# SLM model catalogue
# ---------------------------------------------------------------------------

SLM_MODELS = {
    "qwen-1.5b": {
        "repo_id":     "Qwen/Qwen2.5-1.5B-Instruct-GGUF",
        "filename":    "qwen2.5-1.5b-instruct-q4_k_m.gguf",
        "description": "Qwen2.5-1.5B (Q4_K_M) — ~1 GB RAM, VM-safe",
        "n_ctx":       4096,
        "chat_format": "chatml",
    },
    "phi3-mini": {
        "repo_id":     "microsoft/Phi-3-mini-4k-instruct-gguf",
        "filename":    "Phi-3-mini-4k-instruct-q4.gguf",
        "description": "Phi-3-mini (Q4) — ~2.2 GB RAM, higher quality",
        "n_ctx":       4096,
        "chat_format": "chatml",
    },
}

SLM_CACHE_DIR = Path.home() / ".threatmap" / "models"


# ---------------------------------------------------------------------------
# Provider enum
# ---------------------------------------------------------------------------

class LLMProvider(Enum):
    NONE   = "none"
    SLM    = "slm"
    GROQ   = "groq"
    OPENAI = "openai"
    GEMINI = "gemini"


# ---------------------------------------------------------------------------
# Rule engine — Tier 0 data
# ---------------------------------------------------------------------------

PORT_SERVICE_MAP: dict[str, str] = {
    "21": "ftp",        "22": "ssh",       "23": "telnet",
    "25": "smtp",       "53": "dns",       "80": "http",
    "110": "pop3",      "111": "rpcbind",  "143": "imap",
    "443": "https",     "445": "smb",      "465": "smtps",
    "873": "rsync",     "993": "imaps",    "995": "pop3s",
    "1433": "mssql",    "1521": "oracle",  "2049": "nfs",
    "3306": "mysql",    "3389": "rdp",     "5432": "postgres",
    "5900": "vnc",      "6379": "redis",   "8080": "http-alt",
    "8443": "https-alt","9100": "jetdirect","9200": "elastic",
    "11211": "memcached","27017": "mongodb",
}

PORT_CVSS: dict[str, float] = {
    "21": 7.5,  "22": 5.3,  "23": 9.1,  "25": 5.8,  "53": 6.5,
    "80": 5.0,  "110": 5.8, "111": 7.2, "143": 5.8, "443": 3.7,
    "445": 9.8, "465": 5.8, "873": 7.5, "993": 5.8, "995": 5.8,
    "1433": 8.1,"1521": 8.5,"2049": 7.5,"3306": 7.2,"3389": 8.8,
    "5432": 7.2,"5900": 8.0,"6379": 9.8,"8080": 5.0,"9100": 7.5,
    "9200": 9.8,"11211": 8.0,"27017": 9.8,
}

CVSS_BANDS = [
    ((9.0, 10.0), ("Critical", 1, "Exploit-ready or KEV listed. Patch within 24h.")),
    ((7.0,  8.9), ("High",     2, "Patch within 7 days.")),
    ((4.0,  6.9), ("Medium",   3, "Fix within 30 days.")),
    ((0.1,  3.9), ("Low",      4, "Quarterly review.")),
    ((0.0,  0.0), ("Info",     5, "Informational.")),
]

# Rule-based fallback content matching the reference report style
RULE_OBSERVATIONS: dict[str, dict] = {
    "ssh": {
        "observation_name":    "SSH Remote Access Exposed to Internet",
        "impacted_module":     "Remote Access",
        "risk_impact":         "Allows brute-force and credential-stuffing attacks 24/7, potentially granting full shell access.",
        "recommendation":      "Restrict port 22 to specific trusted IPs via firewall. Disable password authentication and enforce SSH key-based login. Deploy fail2ban.",
    },
    "ftp": {
        "observation_name":    "Insecure FTP Service Detected",
        "impacted_module":     "File Transfer",
        "risk_impact":         "FTP transmits credentials and file content in plaintext; any passive observer can intercept them.",
        "recommendation":      "Disable FTP and replace with SFTP or FTPS. Block port 21 at the firewall.",
    },
    "telnet": {
        "observation_name":    "Insecure Telnet Service Exposed",
        "impacted_module":     "Remote Access",
        "risk_impact":         "All session data including credentials travels in cleartext and can be intercepted.",
        "recommendation":      "Disable Telnet immediately. Replace with SSH for all remote access.",
    },
    "http": {
        "observation_name":    "Cleartext HTTP Web Service Detected",
        "impacted_module":     "Web Server",
        "risk_impact":         "Session tokens, form data, and user credentials can be intercepted by any network observer.",
        "recommendation":      "Redirect all HTTP to HTTPS with a 301 redirect. Implement HSTS (Strict-Transport-Security, min-age 31536000).",
    },
    "https": {
        "observation_name":    "HTTPS TLS Configuration Review Required",
        "impacted_module":     "Web Server",
        "risk_impact":         "Weak TLS settings may allow protocol downgrade attacks and expose users to interception.",
        "recommendation":      "Enforce TLS 1.2+. Disable TLS 1.0/1.1 and weak ciphers (RC4, DES). Add HSTS and full security header suite.",
    },
    "rdp": {
        "observation_name":    "Windows RDP Accessible from Internet",
        "impacted_module":     "Remote Desktop",
        "risk_impact":         "RDP is the primary ransomware entry point. Brute-force or vulnerability exploitation grants full Windows access.",
        "recommendation":      "Block port 3389 at the firewall. Expose RDP only through a VPN. Enable Network Level Authentication (NLA). Patch Windows immediately.",
    },
    "smb": {
        "observation_name":    "Windows SMB File Sharing Exposed to Internet",
        "impacted_module":     "File Sharing",
        "risk_impact":         "Critical — remote unauthenticated code execution possible via EternalBlue (MS17-010). Data on shares accessible to attackers.",
        "recommendation":      "Block port 445 at the perimeter firewall immediately. Apply MS17-010 patch. Disable SMBv1 via Group Policy.",
    },
    "smtps": {
        "observation_name":    "SMTP Mail Service Publicly Accessible",
        "impacted_module":     "Mail Server",
        "risk_impact":         "May allow brute-force attacks against email credentials or abuse for spam relay.",
        "recommendation":      "Restrict SMTP access to trusted mail relay IPs. Implement rate limiting and authentication monitoring.",
    },
    "smtp": {
        "observation_name":    "SMTP Mail Service Publicly Accessible",
        "impacted_module":     "Mail Server",
        "risk_impact":         "May allow brute-force attacks against email credentials or open relay abuse.",
        "recommendation":      "Restrict SMTP to trusted IPs. Enable SPF, DKIM and DMARC. Disable open relay.",
    },
    "mysql": {
        "observation_name":    "MySQL Database Exposed to Internet",
        "impacted_module":     "Database",
        "risk_impact":         "Direct database access bypasses all application security. Credential compromise exposes all application data.",
        "recommendation":      "Bind MySQL to localhost (127.0.0.1). Block port 3306 at the firewall. Application should connect via localhost only.",
    },
    "mssql": {
        "observation_name":    "Microsoft SQL Server Accessible from Internet",
        "impacted_module":     "Database",
        "risk_impact":         "Credential compromise allows full database access and potential OS command execution via stored procedures.",
        "recommendation":      "Block port 1433 at the firewall. Restrict to application server IP only. Disable SA account.",
    },
    "mongodb": {
        "observation_name":    "MongoDB Database Publicly Accessible",
        "impacted_module":     "Database",
        "risk_impact":         "Unauthenticated read/write access to all databases, enabling data theft or ransomware injection.",
        "recommendation":      "Enable MongoDB authentication immediately. Bind to localhost. Block port 27017 externally.",
    },
    "redis": {
        "observation_name":    "Redis Cache Exposed to Internet",
        "impacted_module":     "Cache Layer",
        "risk_impact":         "Unauthenticated access allows cache poisoning, data exfiltration, and in many configs arbitrary code execution.",
        "recommendation":      "Enable requirepass authentication. Bind Redis to 127.0.0.1. Block port 6379. Rename dangerous commands.",
    },
    "elastic": {
        "observation_name":    "Elasticsearch Index Publicly Accessible",
        "impacted_module":     "Search Engine",
        "risk_impact":         "Unauthenticated read access to all indexed data. Large-scale data breaches commonly originate from exposed Elasticsearch.",
        "recommendation":      "Enable X-Pack security with authentication. Bind to internal network. Block port 9200 at the perimeter.",
    },
    "vnc": {
        "observation_name":    "VNC Remote Desktop Service Exposed",
        "impacted_module":     "Remote Desktop",
        "risk_impact":         "Remote graphical access to the system. Weak or no authentication leads to full desktop control.",
        "recommendation":      "VPN-gate VNC access. Require strong authentication. Restrict to known IPs via firewall.",
    },
    "jetdirect": {
        "observation_name":    "Printer/Raw Print Service Exposed",
        "impacted_module":     "Network Service",
        "risk_impact":         "Exposed print services can leak data, enable unauthorized printing, or serve as lateral movement pivot.",
        "recommendation":      "Block port 9100 at the firewall. Restrict printer access to the internal network only.",
    },
    "memcached": {
        "observation_name":    "Memcached Cache Service Exposed",
        "impacted_module":     "Cache Layer",
        "risk_impact":         "Unauthenticated access exposes cached data. UDP amplification attacks possible for DDoS.",
        "recommendation":      "Bind to localhost only. Disable UDP. Block port 11211 externally.",
    },
    "rpcbind": {
        "observation_name":    "RPC Portmapper Service Exposed",
        "impacted_module":     "Network Service",
        "risk_impact":         "Exposes list of running RPC services; often precursor to NFS exploitation.",
        "recommendation":      "Block port 111 at the perimeter. Disable rpcbind if NFS is not required.",
    },
}

DEFAULT_RULE = {
    "observation_name":    "Unnecessary Network Service Exposed",
    "impacted_module":     "Network Service",
    "risk_impact":         "Unnecessary exposed services increase attack surface and may contain unpatched vulnerabilities.",
    "recommendation":      "Identify the purpose of this service. Disable it or restrict access via firewall if not required.",
}


# ---------------------------------------------------------------------------
# SLM Manager
# ---------------------------------------------------------------------------

class SLMManager:
    _instance_lock = threading.Lock()
    _llm_instance  = None

    def __init__(self, preset: str = "qwen-1.5b"):
        self.preset = preset
        self.config = SLM_MODELS.get(preset, SLM_MODELS["qwen-1.5b"])
        self.llm    = None
        self.ready  = False
        self._load()

    def _load(self) -> None:
        try:
            from llama_cpp import Llama
        except ImportError:
            logger.warning(
                "[SLM] llama-cpp-python not installed.\n"
                "      pip install llama-cpp-python huggingface_hub\n"
                "      Then: python3 setup_slm.py"
            )
            return

        model_path = self._ensure_model()
        if not model_path:
            return

        with self._instance_lock:
            if SLMManager._llm_instance is not None:
                self.llm   = SLMManager._llm_instance
                self.ready = True
                return

            n_threads = int(os.getenv("THREATMAP_SLM_THREADS",
                                      str(os.cpu_count() or 4)))
            logger.info("[SLM] Loading %s on %d threads...",
                        self.config["filename"], n_threads)
            try:
                self.llm = Llama(
                    model_path=str(model_path),
                    n_ctx=self.config["n_ctx"],
                    n_threads=n_threads,
                    n_gpu_layers=0,
                    verbose=False,
                    chat_format=self.config["chat_format"],
                )
                SLMManager._llm_instance = self.llm
                self.ready = True
                logger.info("[SLM] Ready: %s", self.config["description"])
            except Exception as exc:
                logger.error("[SLM] Load failed: %s", exc)

    def _ensure_model(self) -> Path | None:
        SLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        model_path = SLM_CACHE_DIR / self.config["filename"]

        if model_path.exists():
            logger.info("[SLM] Model: %s (%.1f GB)",
                        model_path.name, model_path.stat().st_size / 1e9)
            return model_path

        try:
            from huggingface_hub import hf_hub_download
        except ImportError:
            logger.warning(
                "[SLM] huggingface_hub not installed: pip install huggingface_hub\n"
                "      Or manually download: huggingface.co/%s/resolve/main/%s\n"
                "      Save to: %s",
                self.config["repo_id"], self.config["filename"], SLM_CACHE_DIR,
            )
            return None

        logger.info("[SLM] Downloading %s — one-time ~1 GB download...",
                    self.config["filename"])
        try:
            downloaded = hf_hub_download(
                repo_id=self.config["repo_id"],
                filename=self.config["filename"],
                local_dir=str(SLM_CACHE_DIR),
                local_dir_use_symlinks=False,
            )
            path = Path(downloaded)
            logger.info("[SLM] Downloaded: %.1f GB", path.stat().st_size / 1e9)
            return path
        except Exception as exc:
            logger.error("[SLM] Download failed: %s", exc)
            return None

    def generate(self, prompt: str, max_tokens: int = 500) -> str | None:
        if not self.ready or not self.llm:
            return None
        try:
            resp = self.llm.create_chat_completion(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior penetration tester. "
                            "Respond ONLY with valid JSON. No markdown, no explanation."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
                temperature=0.15,
                top_p=0.9,
                repeat_penalty=1.1,
            )
            return resp["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.warning("[SLM] Inference error: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Triage Engine
# ---------------------------------------------------------------------------

class TriageEngine:

    def __init__(self):
        self.provider = LLMProvider.NONE
        self._slm: SLMManager | None = None

        if os.getenv("THREATMAP_SLM_DISABLE", "").strip() != "1":
            self._try_init_slm()

        if self.provider == LLMProvider.NONE:
            cloud = self._detect_cloud()
            if cloud:
                self.provider = cloud

        logger.info("[Triage] Provider: %s", self.provider.value)

    def _try_init_slm(self) -> None:
        preset = os.getenv("THREATMAP_SLM_MODEL", "qwen-1.5b").lower()
        if preset not in SLM_MODELS:
            preset = "qwen-1.5b"
        try:
            slm = SLMManager(preset=preset)
            if slm.ready:
                self._slm     = slm
                self.provider = LLMProvider.SLM
        except Exception as exc:
            logger.warning("[SLM] Init failed: %s", exc)

    def _detect_cloud(self) -> LLMProvider | None:
        raw = os.getenv("THREATMAP_LLM_PROVIDER", "").lower()
        key = os.getenv("THREATMAP_LLM_API_KEY", "")
        if raw == "groq"   and key: return LLMProvider.GROQ
        if raw == "openai" and key: return LLMProvider.OPENAI
        if raw == "gemini" and key: return LLMProvider.GEMINI
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def triage(self, finding: dict, ctx: dict | None = None) -> dict:
        """Always returns a valid result dict."""
        base = self._rule_triage(finding)

        if self.provider == LLMProvider.NONE:
            return base

        try:
            prompt = self._build_prompt(finding, base, ctx or {})
            raw    = self._call(prompt)
            if raw:
                parsed = self._parse_json(raw)
                # Validate the expected keys are present and non-empty
                required = {"observation_name", "detailed_observation",
                            "impacted_module", "risk_impact", "recommendation"}
                if parsed and required.issubset(parsed.keys()):
                    return {**base, **parsed,
                            "ai_enhanced": True,
                            "triage_method": self.provider.value}
        except Exception as exc:
            logger.warning("[Triage] AI failed: %s — using rules.", exc)

        return base

    def run_for_scan(self, db: "DBManager", scan_id: int) -> int:
        db.clear_triage()

        with db._conn() as conn:
            rows = conn.execute(
                """
                SELECT h.id AS host_id, h.url AS host, h.domain,
                       p.port, p.service
                FROM   hosts h
                JOIN   open_ports p ON h.id = p.host_id
                WHERE  h.scan_id = ?
                """,
                (scan_id,),
            ).fetchall()

        contexts = self._build_contexts(scan_id, db)
        count = 0

        for row in rows:
            svc     = (row["service"] or
                       PORT_SERVICE_MAP.get(str(row["port"]), "unknown")).lower()
            finding = {
                "host":    row["host"],
                "domain":  row["domain"],
                "port":    str(row["port"]),
                "service": svc,
            }
            result = self.triage(finding, contexts.get(row["host"], {}))
            result.update({
                "host":    row["host"],
                "port":    str(row["port"]),
                "service": svc,
                "host_id": row["host_id"],
            })
            db.insert_triage(result)
            count += 1
            logger.info(
                "[%s] %s:%s (%s) → %s / %s",
                result["severity"], row["host"], row["port"],
                svc, result["triage_method"],
                result.get("observation_name", "—"),
            )
        return count

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    def _build_contexts(self, scan_id: int, db: "DBManager") -> dict:
        import glob
        ctxs: dict[str, dict] = {}

        with db._conn() as conn:
            host_rows = conn.execute(
                """
                SELECT h.url, h.domain,
                       GROUP_CONCAT(p.port || '/' || COALESCE(p.service,'?'), ', ')
                           AS ports_summary
                FROM   hosts h
                LEFT JOIN open_ports p ON h.id = p.host_id
                WHERE  h.scan_id = ?
                GROUP  BY h.id
                """,
                (scan_id,),
            ).fetchall()

        for row in host_rows:
            host   = row["url"]
            domain = row["domain"]
            ctx: dict = {"ports_summary": row["ports_summary"] or ""}

            # WAF
            try:
                waf = Path(f"reports/wafw00f_{domain}.txt").read_text()
                ctx["waf_detected"] = any(k in waf.lower()
                                          for k in ["is behind", "detected"])
            except FileNotFoundError:
                ctx["waf_detected"] = None

            # WhatWeb
            try:
                data = json.loads(
                    Path(f"reports/whatweb_{domain}.json").read_text())
                ctx["technologies"] = list(set(
                    p for e in data if "plugins" in e
                    for p in e["plugins"].keys()
                ))[:12]
            except Exception:
                ctx["technologies"] = []

            # Nuclei findings
            try:
                lines = [l.strip() for l in
                         Path(f"reports/nuclei_{domain}.txt")
                         .read_text().splitlines() if l.strip()]
                ctx["nuclei_findings"] = lines[:15]
            except FileNotFoundError:
                ctx["nuclei_findings"] = []

            # HTTP evidence
            ev_files = glob.glob(f"reports/evidence_{domain}*.json")
            if ev_files:
                try:
                    ev = json.loads(Path(ev_files[0]).read_text())
                    ctx["http_status"]     = ev.get("status_code")
                    ctx["page_title"]      = ev.get("title")
                    ctx["server"]          = ev.get("server")
                    ctx["missing_headers"] = ev.get("missing_security_headers", [])
                except Exception:
                    pass

            ctxs[host] = ctx
        return ctxs

    # ------------------------------------------------------------------
    # Tier 0: Rule-based triage
    # ------------------------------------------------------------------

    def _rule_triage(self, finding: dict) -> dict:
        port    = str(finding.get("port", ""))
        service = finding.get("service", "").lower()
        cvss    = float(finding.get("cvss_score") or PORT_CVSS.get(port, 0.0))

        severity, priority, sla = self._cvss_band(cvss)

        # Look up service-specific template
        rule = RULE_OBSERVATIONS.get(service, DEFAULT_RULE)

        # Build a specific "Detailed Observations" sentence from actual data
        version = finding.get("version", "")
        detail = (
            f"Port {port}/TCP ({service.upper()}) is publicly accessible"
            f"{f', running {version}' if version else ''}."
        )

        return {
            "severity":             severity,
            "priority_rank":        priority,
            "cvss_score":           cvss,
            "actively_exploited":   False,
            "observation_name":     rule["observation_name"],
            "detailed_observation": detail,
            "impacted_module":      rule["impacted_module"],
            "risk_impact":          rule["risk_impact"],
            "recommendation":       rule["recommendation"],
            # Legacy fields kept for DB compatibility
            "risk_summary":         detail,
            "business_impact":      rule["risk_impact"],
            "remediation":          rule["recommendation"],
            "attack_scenario":      None,
            "false_positive_likelihood": "Low",
            "triage_method":        "rule_based",
            "ai_enhanced":          False,
        }

    def _cvss_band(self, cvss: float) -> tuple:
        for (lo, hi), vals in CVSS_BANDS:
            if lo <= cvss <= hi:
                return vals
        return ("Info", 5, "Review context.")

    # ------------------------------------------------------------------
    # AI prompt — focused on generating the 5 report fields
    # ------------------------------------------------------------------

    def _build_prompt(self, finding: dict, base: dict, ctx: dict) -> str:
        tech     = ", ".join(ctx.get("technologies", [])) or "unknown"
        ports    = ctx.get("ports_summary", "")
        waf      = ("YES" if ctx.get("waf_detected")
                    else "NO" if ctx.get("waf_detected") is False
                    else "not checked")
        nuclei   = "\n".join(ctx.get("nuclei_findings", [])) or "none"
        server   = ctx.get("server", "") or "unknown"
        title    = ctx.get("page_title", "") or "unknown"
        missing  = ", ".join(ctx.get("missing_headers", [])) or "none"

        return f"""You are a senior penetration tester writing a professional vulnerability report.

FINDING:
  Host:    {finding.get("host")}
  Port:    {finding.get("port")}/TCP
  Service: {finding.get("service")}
  CVSS:    {base.get("cvss_score", 0):.1f} ({base.get("severity")})

HOST CONTEXT:
  All open ports:   {ports}
  Technologies:     {tech}
  Server banner:    {server}
  Page title:       {title}
  WAF:              {waf}
  Missing headers:  {missing}

NUCLEI FINDINGS:
{nuclei}

Write a professional vulnerability assessment for this SPECIFIC finding.
Reference actual data above (port, service, version, technologies found).
Keep it concise — like a real pentest report, not a textbook.

Return ONLY valid JSON with exactly these keys:

{{
  "observation_name":     "Short descriptive title (e.g. SSH Remote Access Exposed to Internet)",
  "detailed_observation": "1-2 sentences: what was specifically found. Include port, service, version or version indicator if known.",
  "impacted_module":      "System category (e.g. Remote Access, Web Server, Database, Mail Server, DNS Infrastructure, Application Layer, Network Service)",
  "risk_impact":          "1 sentence: real-world business risk if exploited. Be specific to this host's context.",
  "recommendation":       "Specific prioritised fix steps. Reference configs or commands where relevant."
}}"""

    # ------------------------------------------------------------------
    # Provider dispatch
    # ------------------------------------------------------------------

    def _call(self, prompt: str) -> str | None:
        if self.provider == LLMProvider.SLM:
            return self._slm.generate(prompt)
        if self.provider == LLMProvider.GROQ:
            return self._call_groq(prompt)
        if self.provider == LLMProvider.OPENAI:
            return self._call_openai(prompt)
        if self.provider == LLMProvider.GEMINI:
            return self._call_gemini(prompt)
        return None

    def _call_groq(self, prompt: str) -> str | None:
        if not _REQUESTS_OK: return None
        resp = _requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {os.getenv('THREATMAP_LLM_API_KEY')}"},
            json={
                "model": os.getenv("THREATMAP_LLM_MODEL", "llama3-70b-8192"),
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.15, "max_tokens": 500,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    def _call_openai(self, prompt: str) -> str | None:
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("THREATMAP_LLM_API_KEY"))
        resp = client.chat.completions.create(
            model=os.getenv("THREATMAP_LLM_MODEL", "gpt-4o-mini"),
            messages=[{"role": "user", "content": prompt}],
            temperature=0.15,
            response_format={"type": "json_object"},
        )
        return resp.choices[0].message.content

    def _call_gemini(self, prompt: str) -> str | None:
        if not _REQUESTS_OK: return None
        key   = os.getenv("THREATMAP_LLM_API_KEY")
        model = os.getenv("THREATMAP_LLM_MODEL", "gemini-1.5-flash")
        resp  = _requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={key}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

    @staticmethod
    def _parse_json(raw: str) -> dict:
        try:
            clean = re.sub(r"^```json\s*|^```\s*|```$", "",
                           raw.strip(), flags=re.MULTILINE).strip()
            match = re.search(r"\{.*\}", clean, re.DOTALL)
            if match:
                clean = match.group(0)
            return json.loads(clean)
        except (json.JSONDecodeError, ValueError):
            return {}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_ai_triage(db: "DBManager", scan_id: int) -> int:
    engine = TriageEngine()
    count  = engine.run_for_scan(db, scan_id)
    logger.info("[Triage] Done: %d finding(s) via %s", count, engine.provider.value)
    return count
