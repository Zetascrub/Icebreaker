"""
Bulk importer for Nessus NASL plugin files.

Parses .nasl files using multiprocessing, then bulk-inserts results into the
nessus_plugins table. Designed to handle 288k+ files without running out of
memory or taking hours.

Usage:
    from icebreaker.importers.nessus_importer import NessusImporter
    importer = NessusImporter(db_path="icebreaker.db")
    stats = importer.run("/opt/nessus/lib/nessus/plugins", remote_only=True)
"""
from __future__ import annotations

import json
import multiprocessing
import sqlite3
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from icebreaker.importers.nasl_parser import NASLParser

# Plugin types we consider "runnable" for network scanning
REMOTE_TYPES = {"remote", "combined"}

# Nessus plugin families that are purely local OS checks — skip unless --all
LOCAL_FAMILIES = {
    "AIX Local Security Checks",
    "Alma Linux Local Security Checks",
    "Amazon Linux Local Security Checks",
    "CentOS Local Security Checks",
    "Debian Local Security Checks",
    "Fedora Local Security Checks",
    "FreeBSD Local Security Checks",
    "Gentoo Local Security Checks",
    "HP-UX Local Security Checks",
    "Huawei Local Security Checks",
    "Mandriva Local Security Checks",
    "Miracle Linux Local Security Checks",
    "Oracle Linux Local Security Checks",
    "PhotonOS Local Security Checks",
    "Red Hat Local Security Checks",
    "Rocky Linux Local Security Checks",
    "Scientific Linux Local Security Checks",
    "Slackware Local Security Checks",
    "Solaris Local Security Checks",
    "SuSE Local Security Checks",
    "Ubuntu Local Security Checks",
    "Unity Linux Local Security Checks",
    "VMware ESX Local Security Checks",
    "Windows : Microsoft Bulletins",
    "Windows : User management",
    "MacOS X Local Security Checks",
}

# Batch size for sqlite3 executemany
_BATCH = 500


def _parse_one(path_str: str) -> Optional[Dict[str, Any]]:
    """Worker function: parse a single .nasl file. Runs in a subprocess."""
    try:
        parser = NASLParser()
        meta = parser.parse_file(path_str)
        if not meta:
            return None
        result = parser.to_nessus_plugin_dict(meta)
        if not result or not result.get("nessus_id"):
            return None
        return result
    except Exception:
        return None


class NessusImporter:
    """
    Import NASL plugins from a directory into the nessus_plugins SQLite table.

    Args:
        db_path: Path to the icebreaker SQLite database file.
        workers:  Number of parallel worker processes (default: CPU count).
    """

    INSERT_SQL = """
        INSERT INTO nessus_plugins (
            nessus_id, name, family, plugin_type, category, severity,
            cvss_base_score, cvss3_base_score, cvss_vector, cvss3_vector,
            cve_ids, cwe_id, description, solution, synopsis, see_also,
            cpe_list, required_ports, required_services, required_keys,
            banner_patterns, version_constraints,
            plugin_publication_date, plugin_modification_date, enabled, created_at
        ) VALUES (
            :nessus_id, :name, :family, :plugin_type, :category, :severity,
            :cvss_base_score, :cvss3_base_score, :cvss_vector, :cvss3_vector,
            :cve_ids, :cwe_id, :description, :solution, :synopsis, :see_also,
            :cpe_list, :required_ports, :required_services, :required_keys,
            :banner_patterns, :version_constraints,
            :plugin_publication_date, :plugin_modification_date, 1, CURRENT_TIMESTAMP
        )
        ON CONFLICT(nessus_id) DO UPDATE SET
            name=excluded.name,
            family=excluded.family,
            plugin_type=excluded.plugin_type,
            category=excluded.category,
            severity=excluded.severity,
            cvss_base_score=excluded.cvss_base_score,
            cvss3_base_score=excluded.cvss3_base_score,
            cvss_vector=excluded.cvss_vector,
            cvss3_vector=excluded.cvss3_vector,
            cve_ids=excluded.cve_ids,
            cwe_id=excluded.cwe_id,
            description=excluded.description,
            solution=excluded.solution,
            synopsis=excluded.synopsis,
            see_also=excluded.see_also,
            cpe_list=excluded.cpe_list,
            required_ports=excluded.required_ports,
            required_services=excluded.required_services,
            required_keys=excluded.required_keys,
            banner_patterns=excluded.banner_patterns,
            version_constraints=excluded.version_constraints,
            plugin_publication_date=excluded.plugin_publication_date,
            plugin_modification_date=excluded.plugin_modification_date
    """

    def __init__(self, db_path: str, workers: Optional[int] = None):
        self.db_path = db_path
        self.workers = workers or max(1, multiprocessing.cpu_count() - 1)

    # ------------------------------------------------------------------ #
    # Public                                                               #
    # ------------------------------------------------------------------ #

    def preview(
        self,
        plugins_dir: str,
        sample_size: int = 20,
        remote_only: bool = True,
    ) -> Dict[str, Any]:
        """
        Parse a random sample and return stats without writing to the DB.
        Returns a dict with keys: total_files, sampled, valid, estimated_valid,
        families (Counter), plugin_types (Counter).
        """
        import random
        from collections import Counter

        nasl_files = list(Path(plugins_dir).rglob("*.nasl"))
        total = len(nasl_files)
        if total == 0:
            return {"error": "No .nasl files found"}

        sample = random.sample(nasl_files, min(sample_size, total))
        parser = NASLParser()
        valid = 0
        families: Counter = Counter()
        ptypes: Counter = Counter()
        examples = []

        for f in sample:
            meta = parser.parse_file(str(f))
            if not meta or not meta.get("title"):
                continue
            ptype = meta.get("plugin_type", "unknown")
            family = meta.get("family", "Unknown")
            if remote_only and ptype not in REMOTE_TYPES:
                continue
            valid += 1
            families[family] += 1
            ptypes[ptype] += 1
            if len(examples) < 5:
                examples.append({
                    "title": meta["title"],
                    "severity": meta.get("risk_factor", "INFO"),
                    "family": family,
                    "type": ptype,
                    "cves": meta.get("cve", [])[:3],
                })

        return {
            "total_files": total,
            "sampled": len(sample),
            "valid_in_sample": valid,
            "estimated_valid": int((valid / len(sample)) * total) if sample else 0,
            "top_families": families.most_common(10),
            "plugin_types": dict(ptypes),
            "examples": examples,
        }

    def run(
        self,
        plugins_dir: str,
        remote_only: bool = True,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, int]:
        """
        Import all plugins from plugins_dir into the database.

        Args:
            plugins_dir:       Path to directory containing .nasl files.
            remote_only:       When True (default), skip local-only plugins.
            progress_callback: Optional fn(done, total) called after each batch.

        Returns:
            dict with keys: imported, updated, skipped, errors, total
        """
        nasl_files = list(Path(plugins_dir).rglob("*.nasl"))
        total = len(nasl_files)

        stats = {"imported": 0, "updated": 0, "skipped": 0, "errors": 0, "total": total}
        if total == 0:
            return stats

        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        # Parse in parallel, insert in batches
        file_paths = [str(f) for f in nasl_files]
        batch: List[Dict[str, Any]] = []

        with multiprocessing.Pool(processes=self.workers) as pool:
            for i, result in enumerate(pool.imap_unordered(_parse_one, file_paths, chunksize=50)):
                if result is None:
                    stats["skipped"] += 1
                elif remote_only and result.get("plugin_type") not in REMOTE_TYPES:
                    stats["skipped"] += 1
                else:
                    batch.append(result)

                if len(batch) >= _BATCH:
                    done, updated = self._flush(conn, batch)
                    stats["imported"] += done
                    stats["updated"] += updated
                    batch.clear()

                if progress_callback and (i % 200 == 0 or i == total - 1):
                    progress_callback(i + 1, total)

        # Flush remainder
        if batch:
            done, updated = self._flush(conn, batch)
            stats["imported"] += done
            stats["updated"] += updated

        if progress_callback:
            progress_callback(total, total)

        conn.close()
        return stats

    # ------------------------------------------------------------------ #
    # Private                                                              #
    # ------------------------------------------------------------------ #

    def _flush(self, conn: sqlite3.Connection, batch: List[Dict[str, Any]]) -> Tuple[int, int]:
        """Write a batch to SQLite using executemany. Returns (inserted, updated)."""
        rows = [self._to_row(r) for r in batch]
        imported = 0
        updated = 0
        try:
            cursor = conn.executemany(self.INSERT_SQL, rows)
            conn.commit()
            # SQLite rowcount for INSERT OR REPLACE/ON CONFLICT UPDATE
            # Each affected row increments rowcount; we track conservatively
            imported = len(rows)
        except Exception as e:
            conn.rollback()
            # Fall back to one-by-one to skip the bad row
            for row in rows:
                try:
                    conn.execute(self.INSERT_SQL, row)
                    conn.commit()
                    imported += 1
                except Exception:
                    conn.rollback()
        return imported, updated

    @staticmethod
    def _to_row(d: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize list/dict fields to JSON strings for sqlite3."""
        json_fields = (
            "cve_ids", "see_also", "cpe_list", "required_ports",
            "required_services", "required_keys", "banner_patterns",
            "version_constraints",
        )
        row = dict(d)
        for field in json_fields:
            val = row.get(field)
            if val is None:
                row[field] = "[]"
            elif isinstance(val, (list, dict)):
                row[field] = json.dumps(val)
        # Ensure nullable fields are actually None, not missing
        for nullable in ("cwe_id", "cvss_vector", "cvss3_vector", "description",
                         "solution", "synopsis", "family", "plugin_type",
                         "category", "plugin_publication_date", "plugin_modification_date"):
            row.setdefault(nullable, None)
        return row
