"""
Shared SQLite state for the C2 broker.
Imported by both listener.py (Flask beacon handler) and remote_agent_server.py (MCP tools).
DB file: c2.db in the same directory as this file.
"""

import json
import os
import sqlite3
import time
import uuid

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2.db")

AGENT_STALE_AFTER = 30  # seconds — agent considered offline if no beacon within this window


def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id   TEXT PRIMARY KEY,
                hostname   TEXT,
                os         TEXT,
                username   TEXT,
                ip         TEXT,
                last_seen  REAL,
                metadata   TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS tasks (
                task_id    TEXT PRIMARY KEY,
                agent_id   TEXT,
                type       TEXT,
                payload    TEXT,
                status     TEXT DEFAULT 'pending',
                created_at REAL,
                claimed_at REAL
            );
            CREATE TABLE IF NOT EXISTS results (
                task_id      TEXT PRIMARY KEY,
                agent_id     TEXT,
                output       TEXT,
                exit_code    INTEGER,
                completed_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_tasks_agent_status
                ON tasks (agent_id, status);
        """)


def upsert_agent(agent_id, hostname, os_name, username, ip, metadata=None):
    with _conn() as c:
        c.execute("""
            INSERT INTO agents (agent_id, hostname, os, username, ip, last_seen, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname  = excluded.hostname,
                os        = excluded.os,
                username  = excluded.username,
                ip        = excluded.ip,
                last_seen = excluded.last_seen,
                metadata  = excluded.metadata
        """, (agent_id, hostname, os_name, username, ip, time.time(),
              json.dumps(metadata or {})))


def pop_tasks(agent_id):
    """Atomically claim and return all pending tasks for an agent."""
    with _conn() as c:
        rows = c.execute("""
            SELECT task_id, type, payload FROM tasks
            WHERE agent_id = ? AND status = 'pending'
            ORDER BY created_at
        """, (agent_id,)).fetchall()
        if rows:
            ids = [r["task_id"] for r in rows]
            placeholders = ",".join("?" * len(ids))
            c.execute(
                f"UPDATE tasks SET status='claimed', claimed_at=? WHERE task_id IN ({placeholders})",
                [time.time()] + ids,
            )
    return [dict(r) for r in rows]


def store_results(results):
    with _conn() as c:
        for r in results:
            c.execute("""
                INSERT OR REPLACE INTO results
                    (task_id, agent_id, output, exit_code, completed_at)
                VALUES (?, ?, ?, ?, ?)
            """, (r["task_id"], r.get("agent_id", ""),
                  r.get("output", ""), r.get("exit_code", 0), time.time()))
            c.execute("UPDATE tasks SET status='done' WHERE task_id=?", (r["task_id"],))


def queue_task(agent_id, task_type, payload: dict) -> str:
    task_id = str(uuid.uuid4())
    with _conn() as c:
        c.execute("""
            INSERT INTO tasks (task_id, agent_id, type, payload, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
        """, (task_id, agent_id, task_type, json.dumps(payload), time.time()))
    return task_id


def get_result(task_id):
    with _conn() as c:
        row = c.execute("SELECT * FROM results WHERE task_id=?", (task_id,)).fetchone()
        return dict(row) if row else None


def all_agents():
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM agents ORDER BY last_seen DESC"
        ).fetchall()]


def active_agents():
    cutoff = time.time() - AGENT_STALE_AFTER
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM agents WHERE last_seen > ? ORDER BY last_seen DESC",
            (cutoff,),
        ).fetchall()]


def get_agent(agent_id):
    with _conn() as c:
        row = c.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return dict(row) if row else None


def delete_agent(agent_id):
    with _conn() as c:
        c.execute("DELETE FROM results WHERE agent_id=?", (agent_id,))
        c.execute("DELETE FROM tasks   WHERE agent_id=?", (agent_id,))
        c.execute("DELETE FROM agents  WHERE agent_id=?", (agent_id,))
