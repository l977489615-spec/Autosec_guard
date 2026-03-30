import os
import sqlite3
from datetime import date, datetime
from pathlib import Path

import pymysql


SOURCE_URI = os.environ.get("AUTOSEC_SOURCE_DB_URI", "mysql+pymysql://root:1@localhost:3306/autosec_db")
TARGET_SQLITE_PATH = Path(os.environ.get("AUTOSEC_TARGET_SQLITE_PATH", "server/autosec.db"))


def parse_mysql_uri(uri: str) -> dict:
    if not uri.startswith("mysql+pymysql://"):
        raise ValueError("AUTOSEC_SOURCE_DB_URI must start with mysql+pymysql://")

    payload = uri[len("mysql+pymysql://"):]
    creds, host_db = payload.split("@", 1)
    username, password = creds.split(":", 1)
    host_port, database = host_db.split("/", 1)
    if ":" in host_port:
        host, port = host_port.split(":", 1)
        port = int(port)
    else:
        host, port = host_port, 3306

    return {
        "host": host,
        "port": port,
        "user": username,
        "password": password,
        "database": database,
    }


def ensure_sqlite_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at DATETIME
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            session_id TEXT,
            target_ip TEXT,
            target_mac TEXT,
            status TEXT NOT NULL,
            started_at DATETIME,
            completed_at DATETIME,
            results_json TEXT,
            logs TEXT,
            risk_score INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    conn.commit()


def normalize_rows(rows: list[dict]) -> list[dict]:
    normalized = []
    for row in rows:
        copy = dict(row)
        for key, value in copy.items():
            if isinstance(value, (datetime, date)):
                copy[key] = value.isoformat(sep=" ")
        normalized.append(copy)
    return normalized


def main() -> None:
    mysql_config = parse_mysql_uri(SOURCE_URI)
    target_path = TARGET_SQLITE_PATH.resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    mysql_conn = pymysql.connect(
        host=mysql_config["host"],
        port=mysql_config["port"],
        user=mysql_config["user"],
        password=mysql_config["password"],
        database=mysql_config["database"],
        cursorclass=pymysql.cursors.DictCursor,
    )
    sqlite_conn = sqlite3.connect(target_path)
    sqlite_conn.row_factory = sqlite3.Row

    try:
        ensure_sqlite_schema(sqlite_conn)

        with mysql_conn.cursor() as cur:
            cur.execute("SELECT id, username, password_hash, role, created_at FROM users ORDER BY id ASC")
            users = normalize_rows(cur.fetchall())
            cur.execute("""
                SELECT id, user_id, session_id, target_ip, target_mac, status,
                       started_at, completed_at, results_json, logs, risk_score
                FROM scan_history
                ORDER BY id ASC
            """)
            histories = normalize_rows(cur.fetchall())

        sqlite_conn.execute("DELETE FROM scan_history")
        sqlite_conn.execute("DELETE FROM users")

        sqlite_conn.executemany(
            """
            INSERT INTO users (id, username, password_hash, role, created_at)
            VALUES (:id, :username, :password_hash, :role, :created_at)
            """,
            users,
        )
        sqlite_conn.executemany(
            """
            INSERT INTO scan_history (
                id, user_id, session_id, target_ip, target_mac, status,
                started_at, completed_at, results_json, logs, risk_score
            )
            VALUES (
                :id, :user_id, :session_id, :target_ip, :target_mac, :status,
                :started_at, :completed_at, :results_json, :logs, :risk_score
            )
            """,
            histories,
        )

        sqlite_conn.commit()
        print(
            {
                "target_sqlite": str(target_path),
                "users_migrated": len(users),
                "scan_history_migrated": len(histories),
            }
        )
    finally:
        sqlite_conn.close()
        mysql_conn.close()


if __name__ == "__main__":
    main()
