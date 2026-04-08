#!/usr/bin/env python3
"""
db_patch.py — ThreatMap Infra database migration helper

Adds 4 new columns to the triage table that support the
updated professional report format:

  observation_name     — short finding title
  detailed_observation — factual what-was-found sentence
  impacted_module      — system category
  risk_impact          — one-sentence business risk

Run this ONCE if you have an existing threatmap.db from a previous version:
  python3 db_patch.py

Safe to run multiple times — skips columns that already exist.
"""

import sqlite3
from pathlib import Path

DB_PATH = "threatmap.db"

NEW_COLUMNS = [
    ("observation_name",     "TEXT"),
    ("detailed_observation", "TEXT"),
    ("impacted_module",      "TEXT"),
    ("risk_impact",          "TEXT"),
]


def patch(db_path: str = DB_PATH) -> None:
    if not Path(db_path).exists():
        print(f"[!] {db_path} not found — run a scan first to create it.")
        return

    conn = sqlite3.connect(db_path)
    cur  = conn.execute("PRAGMA table_info(triage)")
    existing = {row[1] for row in cur.fetchall()}

    added = []
    for col_name, col_type in NEW_COLUMNS:
        if col_name not in existing:
            conn.execute(
                f"ALTER TABLE triage ADD COLUMN {col_name} {col_type}"
            )
            added.append(col_name)
            print(f"  ✔  Added column: {col_name}")
        else:
            print(f"  ○  Already exists: {col_name}")

    conn.commit()
    conn.close()

    if added:
        print(f"\nMigration complete. {len(added)} column(s) added to triage table.")
        print("Re-run your next scan — new fields will be populated automatically.")
    else:
        print("\nDatabase is already up to date. No changes needed.")


if __name__ == "__main__":
    patch()
