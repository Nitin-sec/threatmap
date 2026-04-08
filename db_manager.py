"""
db_manager.py — ThreatMap SQLite persistence layer.

Schema
------
scans        — one row per pipeline run
hosts        — one row per live HTTP/S host discovered
open_ports   — nmap results, child of hosts
screenshots  — EyeWitness output paths, child of hosts
terminal_logs — script(1) recordings, child of scans
"""

import sqlite3
import os
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

# Default DB location — always inside the reports/ directory so it gets
# wiped with the rest of the artefacts on the next run if the caller
# calls ensure_env() first.
# DB lives in the project root — NOT inside reports/ which gets wiped each run
DEFAULT_DB_PATH = "threatmap.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DBManager:
    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._migrate_schema()   # must run BEFORE _init_schema
        self._init_schema()

    def _migrate_schema(self) -> None:
        """
        Detect and repair schema drift from older versions of the tool.

        Old ai_triage.py created a 4-column `triage` table.  The current
        schema has 17 columns.  `CREATE TABLE IF NOT EXISTS` silently
        skips creation when the table already exists, so we must detect
        the stale schema and rebuild it ourselves.
        """
        if not Path(self.db_path).exists():
            return   # fresh DB — nothing to migrate

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("PRAGMA table_info(triage)")
            columns = {row[1] for row in cursor.fetchall()}
        finally:
            conn.close()

        if columns and "host_id" not in columns:
            # Old schema detected — drop and let _init_schema recreate
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("DROP TABLE IF EXISTS triage")
                conn.commit()
                print("[DB] Migrated stale triage table to current schema.")
            finally:
                conn.close()

    @contextmanager
    def _conn(self):
        """Thread-safe connection context manager with WAL mode."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent readers
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target      TEXT    NOT NULL,
                    scan_mode   TEXT    NOT NULL,
                    max_workers INTEGER DEFAULT 2,
                    started_at  TEXT    NOT NULL,
                    completed_at TEXT,
                    status      TEXT    DEFAULT 'running'
                );

                CREATE TABLE IF NOT EXISTS hosts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id      INTEGER NOT NULL,
                    url          TEXT    NOT NULL,
                    domain       TEXT    NOT NULL,
                    discovered_at TEXT   NOT NULL,
                    UNIQUE(scan_id, url),
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );

                CREATE TABLE IF NOT EXISTS open_ports (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id  INTEGER NOT NULL,
                    port     TEXT    NOT NULL,
                    state    TEXT    NOT NULL,
                    service  TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                );

                CREATE TABLE IF NOT EXISTS screenshots (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id          INTEGER NOT NULL,
                    url              TEXT    NOT NULL,
                    screenshot_path  TEXT,
                    http_status      INTEGER,
                    page_title       TEXT,
                    eyewitness_dir   TEXT,
                    captured_at      TEXT    NOT NULL,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                );

                CREATE TABLE IF NOT EXISTS terminal_logs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id     INTEGER NOT NULL,
                    command     TEXT    NOT NULL,
                    log_path    TEXT    NOT NULL,
                    recorded_at TEXT    NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );

                CREATE TABLE IF NOT EXISTS triage (
                    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id                   INTEGER,
                    host                      TEXT    NOT NULL,
                    port                      TEXT    NOT NULL,
                    service                   TEXT,
                    severity                  TEXT    NOT NULL,
                    priority_rank             INTEGER DEFAULT 5,
                    cvss_score                REAL    DEFAULT 0.0,
                    actively_exploited        INTEGER DEFAULT 0,
                    risk_summary              TEXT,
                    remediation               TEXT,
                    business_impact           TEXT,
                    false_positive_likelihood TEXT,
                    attack_scenario           TEXT,
                    triage_method             TEXT    DEFAULT 'rule_based',
                    ai_enhanced               INTEGER DEFAULT 0,
                    triaged_at                TEXT    NOT NULL,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                );
            """)

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def init_scan(self, target: str, scan_mode: str, max_workers: int) -> int:
        """Create a new scan record and return its id."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (target, scan_mode, max_workers, started_at) VALUES (?,?,?,?)",
                (target, scan_mode, max_workers, _now()),
            )
            return cur.lastrowid

    def complete_scan(self, scan_id: int) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE scans SET completed_at=?, status='completed' WHERE id=?",
                (_now(), scan_id),
            )

    def fail_scan(self, scan_id: int, reason: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE scans SET completed_at=?, status=? WHERE id=?",
                (_now(), f"failed: {reason}", scan_id),
            )

    # ------------------------------------------------------------------
    # Hosts
    # ------------------------------------------------------------------

    def upsert_host(self, scan_id: int, url: str, domain: str) -> int:
        """Insert host or return existing id (idempotent)."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO hosts (scan_id, url, domain, discovered_at)
                VALUES (?,?,?,?)
                ON CONFLICT(scan_id, url) DO NOTHING
                """,
                (scan_id, url, domain, _now()),
            )
            row = conn.execute(
                "SELECT id FROM hosts WHERE scan_id=? AND url=?", (scan_id, url)
            ).fetchone()
            return row["id"]

    def insert_ports(self, host_id: int, ports: list[dict]) -> None:
        """Bulk-insert nmap port results for a host."""
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO open_ports (host_id, port, state, service) VALUES (?,?,?,?)",
                [
                    (host_id, p["port"], p.get("state", "open"), p.get("service", "unknown"))
                    for p in ports
                ],
            )

    # ------------------------------------------------------------------
    # Screenshots
    # ------------------------------------------------------------------

    def upsert_screenshot(
        self,
        host_id: int,
        url: str,
        screenshot_path: str | None,
        eyewitness_dir: str | None = None,
        http_status: int | None = None,
        page_title: str | None = None,
    ) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO screenshots
                    (host_id, url, screenshot_path, eyewitness_dir,
                     http_status, page_title, captured_at)
                VALUES (?,?,?,?,?,?,?)
                """,
                (host_id, url, screenshot_path, eyewitness_dir,
                 http_status, page_title, _now()),
            )
            return cur.lastrowid

    def get_screenshots_for_scan(self, scan_id: int) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return conn.execute(
                """
                SELECT s.url, s.screenshot_path, s.http_status, s.page_title,
                       s.captured_at, s.eyewitness_dir
                FROM   screenshots s
                JOIN   hosts h ON s.host_id = h.id
                WHERE  h.scan_id = ?
                ORDER BY s.captured_at
                """,
                (scan_id,),
            ).fetchall()

    # ------------------------------------------------------------------
    # Terminal logs
    # ------------------------------------------------------------------

    def insert_terminal_log(self, scan_id: int, command: str, log_path: str) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO terminal_logs (scan_id, command, log_path, recorded_at) VALUES (?,?,?,?)",
                (scan_id, command, log_path, _now()),
            )
            return cur.lastrowid

    def get_terminal_logs_for_scan(self, scan_id: int) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return conn.execute(
                "SELECT command, log_path, recorded_at FROM terminal_logs WHERE scan_id=? ORDER BY recorded_at",
                (scan_id,),
            ).fetchall()

    # ------------------------------------------------------------------
    # Triage
    # ------------------------------------------------------------------

    def clear_triage(self) -> None:
        """Wipe triage table before a fresh run to avoid duplicate rows."""
        with self._conn() as conn:
            conn.execute("DELETE FROM triage")

    def insert_triage(self, record: dict) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO triage (
                    host_id, host, port, service, severity, priority_rank,
                    cvss_score, actively_exploited, risk_summary, remediation,
                    business_impact, false_positive_likelihood, attack_scenario,
                    triage_method, ai_enhanced, triaged_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    record.get("host_id"),
                    record["host"],
                    record["port"],
                    record.get("service"),
                    record["severity"],
                    record.get("priority_rank", 5),
                    record.get("cvss_score", 0.0),
                    int(record.get("actively_exploited", False)),
                    record.get("risk_summary"),
                    record.get("remediation"),
                    record.get("business_impact"),
                    record.get("false_positive_likelihood"),
                    record.get("attack_scenario"),
                    record.get("triage_method", "rule_based"),
                    int(record.get("ai_enhanced", False)),
                    _now(),
                ),
            )
            return cur.lastrowid

    def get_all_triage(self) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return conn.execute(
                """
                SELECT t.*, s.screenshot_path
                FROM   triage t
                LEFT JOIN hosts h ON t.host_id = h.id
                LEFT JOIN screenshots s ON s.host_id = h.id
                ORDER BY t.priority_rank ASC, t.severity DESC
                """
            ).fetchall()

    # ------------------------------------------------------------------
    # Evidence HTML report
    # ------------------------------------------------------------------

    def generate_evidence_report(self, scan_id: int, output_path: str) -> None:
        """
        Produce a self-contained HTML evidence gallery for the given scan.

        Each host section shows:
          • Screenshot thumbnail (embedded as base64 if the file exists)
          • HTTP status, page title
          • Open ports table
          • Links to terminal log files
        """
        screenshots = self.get_screenshots_for_scan(scan_id)
        terminal_logs = self.get_terminal_logs_for_scan(scan_id)

        with self._conn() as conn:
            scan_row = conn.execute(
                "SELECT target, started_at, completed_at, scan_mode FROM scans WHERE id=?",
                (scan_id,),
            ).fetchone()

        target = scan_row["target"] if scan_row else "unknown"
        started = scan_row["started_at"] if scan_row else ""
        completed = scan_row["completed_at"] or "In Progress"

        # Build screenshot cards
        cards_html = ""
        if screenshots:
            for row in screenshots:
                img_tag = _build_img_tag(row["screenshot_path"])
                status_badge = _status_badge(row["http_status"])
                title = row["page_title"] or "<em>no title</em>"
                cards_html += f"""
                <div class="card">
                    <div class="card-header">
                        <span class="url">{_esc(row['url'])}</span>
                        {status_badge}
                    </div>
                    <div class="card-body">
                        {img_tag}
                        <div class="meta">
                            <p><strong>Title:</strong> {title}</p>
                            <p><strong>Captured:</strong> {row['captured_at']}</p>
                        </div>
                    </div>
                </div>"""
        else:
            cards_html = "<p class='empty'>No screenshots were captured for this scan.</p>"

        # Build terminal log table
        logs_html = ""
        if terminal_logs:
            logs_html = "<table><thead><tr><th>Command</th><th>Log File</th><th>Recorded At</th></tr></thead><tbody>"
            for log in terminal_logs:
                logs_html += (
                    f"<tr>"
                    f"<td><code>{_esc(log['command'])}</code></td>"
                    f"<td><a href='{_esc(log['log_path'])}'>{_esc(os.path.basename(log['log_path']))}</a></td>"
                    f"<td>{log['recorded_at']}</td>"
                    f"</tr>"
                )
            logs_html += "</tbody></table>"
        else:
            logs_html = "<p class='empty'>No terminal sessions recorded.</p>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatMap Evidence — {_esc(target)}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #58a6ff; --danger: #f85149; --warn: #d29922;
    --ok: #3fb950; --text: #c9d1d9; --muted: #8b949e;
    --radius: 6px; --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }}
  h1 {{ font-size: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: .75rem; margin-bottom: 1.5rem; }}
  h2 {{ font-size: 1.1rem; color: var(--muted); margin: 2rem 0 1rem; text-transform: uppercase; letter-spacing: .08em; }}
  .meta-bar {{ display: flex; gap: 2rem; font-size: .85rem; color: var(--muted); margin-bottom: 2rem; }}
  .meta-bar span strong {{ color: var(--text); }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr)); gap: 1.25rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }}
  .card-header {{ padding: .6rem 1rem; background: #1c2128; border-bottom: 1px solid var(--border);
                  display: flex; justify-content: space-between; align-items: center; gap: .5rem; }}
  .url {{ font-size: .8rem; color: var(--accent); word-break: break-all; font-family: monospace; }}
  .badge {{ font-size: .7rem; font-weight: 700; padding: .2rem .5rem; border-radius: 99px; white-space: nowrap; }}
  .badge-ok   {{ background: #1a3a24; color: var(--ok);   border: 1px solid var(--ok); }}
  .badge-warn {{ background: #3a2e10; color: var(--warn); border: 1px solid var(--warn); }}
  .badge-err  {{ background: #3a1a1a; color: var(--danger); border: 1px solid var(--danger); }}
  .badge-none {{ background: #1c2128; color: var(--muted); border: 1px solid var(--border); }}
  .card-body {{ padding: 1rem; display: flex; gap: 1rem; align-items: flex-start; }}
  .card-body img {{ width: 200px; min-width: 200px; height: 130px; object-fit: cover;
                    border-radius: var(--radius); border: 1px solid var(--border); }}
  .card-body .no-shot {{ width: 200px; min-width: 200px; height: 130px; background: #0d1117;
                         border: 1px dashed var(--border); border-radius: var(--radius);
                         display: flex; align-items: center; justify-content: center;
                         color: var(--muted); font-size: .75rem; }}
  .meta {{ flex: 1; font-size: .82rem; line-height: 1.6; }}
  .meta p {{ color: var(--muted); }} .meta p strong {{ color: var(--text); }}
  table {{ width: 100%; border-collapse: collapse; font-size: .83rem; }}
  thead tr {{ background: #1c2128; }}
  th, td {{ padding: .55rem .75rem; text-align: left; border: 1px solid var(--border); }}
  th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: .72rem; letter-spacing: .05em; }}
  td code {{ color: var(--accent); }}
  td a {{ color: var(--accent); text-decoration: none; }}
  td a:hover {{ text-decoration: underline; }}
  .empty {{ color: var(--muted); font-style: italic; font-size: .9rem; padding: .5rem 0; }}
</style>
</head>
<body>
<h1>🛡 ThreatMap — Visual Evidence Report</h1>
<div class="meta-bar">
  <span><strong>Target:</strong> {_esc(target)}</span>
  <span><strong>Scan Started:</strong> {started}</span>
  <span><strong>Scan Completed:</strong> {completed}</span>
  <span><strong>Screenshots:</strong> {len(screenshots)}</span>
</div>

<h2>📸 Screenshot Gallery</h2>
<div class="grid">
{cards_html}
</div>

<h2>🖥 Terminal Session Recordings</h2>
{logs_html}

</body>
</html>"""

        Path(output_path).write_text(html, encoding="utf-8")
        print(f"    ↳ [DB] Evidence report written → {output_path}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(s: str | None) -> str:
    """Minimal HTML escaping — avoids pulling in html module."""
    if not s:
        return ""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _status_badge(code: int | None) -> str:
    if code is None:
        return '<span class="badge badge-none">N/A</span>'
    if 200 <= code < 300:
        return f'<span class="badge badge-ok">{code}</span>'
    if 300 <= code < 400:
        return f'<span class="badge badge-warn">{code}</span>'
    return f'<span class="badge badge-err">{code}</span>'


def _build_img_tag(path: str | None) -> str:
    """Embed the screenshot as base64 if the file exists, else show placeholder."""
    if path and os.path.isfile(path):
        try:
            data = Path(path).read_bytes()
            b64 = base64.b64encode(data).decode()
            return f'<img src="data:image/png;base64,{b64}" alt="screenshot">'
        except Exception:
            pass
    return '<div class="no-shot">No screenshot</div>'
