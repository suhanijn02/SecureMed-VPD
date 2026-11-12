"""
Database layer: persistent schema (base table + VPD data dictionary) and per-session setup.
The VPD objects themselves (context, secure view, triggers) are defined in security/vpd.py.
"""
import sqlite3

from flask import current_app, g

from security import vpd

SCHEMA = r"""
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT UNIQUE NOT NULL,
    description      TEXT,
    can_insert       INTEGER NOT NULL DEFAULT 0,     -- statement types this role may run
    can_update       INTEGER NOT NULL DEFAULT 0,
    can_delete       INTEGER NOT NULL DEFAULT 0,
    is_policy_admin  INTEGER NOT NULL DEFAULT 0      -- may manage VPD policies (like EXEMPT ACCESS POLICY is NOT granted)
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL COLLATE NOCASE,
    full_name     TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role_id       INTEGER NOT NULL REFERENCES roles(id),
    ward          TEXT                               -- feeds the OWN_WARD policy via the app context
);

-- The protected base table. The application never queries it directly.
CREATE TABLE IF NOT EXISTS patients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mrn         TEXT UNIQUE NOT NULL,
    full_name   TEXT NOT NULL,
    dob         TEXT NOT NULL,
    gender      TEXT NOT NULL CHECK (gender IN ('M','F','O')),
    pincode     TEXT NOT NULL,
    phone       TEXT,
    ward        TEXT NOT NULL,
    doctor_id   INTEGER REFERENCES users(id),
    is_vip      INTEGER NOT NULL DEFAULT 0,
    aadhaar     TEXT,
    diagnosis   TEXT,
    created_at  TEXT,
    updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS ix_patients_doctor ON patients(doctor_id);
CREATE INDEX IF NOT EXISTS ix_patients_ward   ON patients(ward);

-- ---------- VPD data dictionary (cf. DBA_POLICIES / DBA_SEC_RELEVANT_COLS) ---------- --
CREATE TABLE IF NOT EXISTS vpd_policies (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT UNIQUE NOT NULL,
    table_name     TEXT NOT NULL DEFAULT 'patients',
    role_id        INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    predicate_type TEXT NOT NULL CHECK (predicate_type IN ('ALL_ROWS','OWN_PATIENTS','OWN_WARD','NON_VIP','NO_ROWS')),
    enabled        INTEGER NOT NULL DEFAULT 1,
    updated_at     TEXT,
    updated_by     TEXT,
    UNIQUE (role_id, table_name)
);

CREATE TABLE IF NOT EXISTS column_policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id     INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    column_name TEXT NOT NULL CHECK (column_name IN ('aadhaar','diagnosis','phone','dob')),
    action      TEXT NOT NULL CHECK (action IN ('SHOW','MASK','HIDE')),
    UNIQUE (role_id, column_name)
);
"""


def connect(path: str) -> sqlite3.Connection:
    """Open a DB session and install the session-private VPD objects."""
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    vpd.install_session_objects(conn)
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_schema(path: str):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
