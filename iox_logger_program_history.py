"""SQLite-backed execution history for IoX Logger.

The database and configuration live under persist, separate from CSV node logs.
"""
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

RETENTION_OPTIONS = {7, 14, 30, 60, 90, 180, 365}
PAGE_SIZE = 100


class ProgramHistory:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db_path = self.directory / "program_history.sqlite3"
        self.config_path = self.directory / "program_history_config.json"
        self.lock = threading.RLock()
        self.enabled = True
        self.retention_days = 30
        self.last_cleanup = 0
        if self.config_path.exists():
            try:
                data = json.loads(self.config_path.read_text())
                if type(data.get("enabled")) is bool:
                    self.enabled = data["enabled"]
                if data.get("retention_days") in RETENTION_OPTIONS:
                    self.retention_days = data["retention_days"]
            except (OSError, ValueError, TypeError):
                pass
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS executions (id INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, timestamp TEXT NOT NULL, program_name TEXT NOT NULL, program_id TEXT NOT NULL, branch TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS ix_executions_epoch ON executions(epoch)")
            db.execute("CREATE INDEX IF NOT EXISTS ix_executions_name ON executions(program_name)")
        self.db_path.chmod(0o600)
        self.cleanup(force=True)

    def connect(self):
        db = sqlite3.connect(str(self.db_path), timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def cleanup(self, force=False):
        with self.lock:
            now = time.time()
            if not force and now - self.last_cleanup < 300:
                return
            cutoff = int(now - self.retention_days * 86400)
            with self.connect() as db:
                db.execute("DELETE FROM executions WHERE epoch < ?", (cutoff,))
            self.last_cleanup = now

    def settings(self):
        with self.lock:
            return {"enabled": self.enabled, "retention_days": self.retention_days}

    def configure(self, data):
        enabled = data.get("enabled")
        retention = data.get("retention_days")
        if type(enabled) is not bool or type(retention) is not int or retention not in RETENTION_OPTIONS:
            raise ValueError("Invalid settings")
        with self.lock:
            from tempfile import NamedTemporaryFile
            import os
            self.directory.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile("w", dir=self.directory, prefix=".program-", delete=False) as tmp:
                path = Path(tmp.name)
                json.dump({"enabled": enabled, "retention_days": retention}, tmp)
                tmp.write("\n")
                tmp.flush()
                os.fsync(tmp.fileno())
            try:
                path.chmod(0o600)
                os.replace(path, self.config_path)
            finally:
                path.unlink(missing_ok=True)
            self.enabled = enabled
            self.retention_days = retention
            self.cleanup(force=True)
            return self.settings()

    def record(self, name, program_id, branch):
        if branch not in ("THEN", "ELSE"):
            return
        with self.lock:
            if not self.enabled:
                return
            epoch = int(time.time())
            timestamp = datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="seconds")
            with self.connect() as db:
                db.execute("INSERT INTO executions (epoch,timestamp,program_name,program_id,branch) VALUES (?,?,?,?,?)",
                           (epoch, timestamp, str(name), str(program_id), branch))
            self.cleanup()

    @staticmethod
    def criteria(search, sort):
        if not isinstance(search, str) or len(search) > 200:
            raise ValueError("Search too long")
        sorts = {"newest": "id DESC", "oldest": "id ASC", "name": "program_name COLLATE NOCASE ASC, id DESC"}
        if sort not in sorts:
            raise ValueError("Invalid sort")
        if search:
            # Escape LIKE wildcards to make search literal.
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clause = " WHERE (timestamp LIKE ? ESCAPE '\\' OR program_name LIKE ? ESCAPE '\\' OR program_id LIKE ? ESCAPE '\\' OR branch LIKE ? ESCAPE '\\')"
            return clause, ["%" + escaped + "%"] * 4, sorts[sort]
        return "", [], sorts[sort]

    def query(self, search="", sort="newest", page=1):
        if not isinstance(page, int) or not 1 <= page <= 1000000:
            raise ValueError("Invalid page")
        clause, params, ordering = self.criteria(search, sort)
        with self.lock, self.connect() as db:
            total = db.execute("SELECT COUNT(*) FROM executions" + clause, params).fetchone()[0]
            records = db.execute("SELECT timestamp,program_name,program_id,branch FROM executions" + clause + " ORDER BY " + ordering + " LIMIT ? OFFSET ?", params + [PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
        return {"events": [dict(zip(("timestamp", "program_name", "program_id", "branch"), row)) for row in records], "total": total, "page": page, "page_size": PAGE_SIZE}

    def export(self, search="", sort="newest"):
        clause, params, ordering = self.criteria(search, sort)
        with self.connect() as db:
            cursor = db.execute(
                "SELECT timestamp,program_name,program_id,branch FROM executions"
                + clause + " ORDER BY " + ordering, params
            )
            while True:
                batch = cursor.fetchmany(500)
                if not batch:
                    break
                for row in batch:
                    yield row
