"""Small SQLite setup for the synthetic MediShield demo."""

import sqlite3
from pathlib import Path
from typing import Union


PathLike = Union[str, Path]
DEFAULT_DB_PATH = Path("medishield.sqlite3")


def get_connection(db_path: PathLike = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a SQLite connection with rows addressable by column name."""

    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    return connection


def init_db(connection: sqlite3.Connection) -> None:
    """Create the MediShield tables if they do not already exist."""

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS actors (
            actor_id TEXT PRIMARY KEY,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS patients (
            patient_id TEXT PRIMARY KEY,
            name_synthetic TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS approvals (
            approval_id TEXT PRIMARY KEY,
            action_hash TEXT NOT NULL,
            action_json TEXT NOT NULL,
            approver_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            consumed INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS orders (
            order_id TEXT PRIMARY KEY,
            patient_id TEXT NOT NULL,
            medication_id TEXT NOT NULL,
            dose TEXT NOT NULL,
            units TEXT NOT NULL,
            route TEXT NOT NULL,
            frequency TEXT NOT NULL,
            duration TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            request_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            tool TEXT NOT NULL,
            action_type TEXT NOT NULL,
            approval_id TEXT,
            decision TEXT NOT NULL,
            risk TEXT NOT NULL,
            rule TEXT NOT NULL,
            reason TEXT NOT NULL,
            changed_fields TEXT NOT NULL,
            state_changed INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tool_baseline (
            tool_name TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            allowed_destination TEXT NOT NULL
        );
        """
    )
    connection.commit()


def seed_data(connection: sqlite3.Connection) -> None:
    """Insert obviously fake demo records without overwriting team changes."""

    connection.executemany(
        "INSERT OR IGNORE INTO actors(actor_id, role) VALUES (?, ?)",
        [
            ("clinician_1", "clinician"),
            ("nurse_1", "nurse"),
            ("agent_1", "agent"),
        ],
    )
    connection.executemany(
        "INSERT OR IGNORE INTO patients(patient_id, name_synthetic) VALUES (?, ?)",
        [
            ("P-104", "Synthetic Patient Alpha"),
            ("P-205", "Synthetic Patient Beta"),
        ],
    )
    # Keep apply_order as the only order-table writer, including for demo data.
    from guard.models import ProtectedAction
    from .backend import apply_order

    apply_order(
        ProtectedAction(
            patient_id="P-104",
            medication_id="MED-A",
            dose="SIMULATED-5",
            units="synthetic-units",
            route="simulated-route",
            frequency="demo-only",
            duration="demo-duration",
            order_id="ORD-DEMO-001",
        ),
        connection=connection,
    )
    connection.commit()


def initialize_db(db_path: PathLike = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open, create, and seed a synthetic MediShield database."""

    connection = get_connection(db_path)
    init_db(connection)
    seed_data(connection)
    return connection
