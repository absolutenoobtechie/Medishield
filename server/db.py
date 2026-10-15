"""Small SQLite setup for the synthetic MediShield demo."""

import sqlite3
from pathlib import Path
from typing import Union


PathLike = Union[str, Path]
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = REPOSITORY_ROOT / "medishield.sqlite3"


def get_connection(db_path: PathLike = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a SQLite connection with rows addressable by column name."""

    target = Path(db_path)
    if not target.is_absolute() and str(target) != ":memory:":
        cwd = Path.cwd().resolve()
        try:
            inside_repository = cwd.is_relative_to(REPOSITORY_ROOT)
        except AttributeError:
            inside_repository = str(cwd).startswith(str(REPOSITORY_ROOT))
        if inside_repository:
            target = REPOSITORY_ROOT / target
    if str(target) != ":memory:":
        target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(target))
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
            name_synthetic TEXT NOT NULL,
            org_id TEXT
        );

        CREATE TABLE IF NOT EXISTS approvals (
            approval_id TEXT PRIMARY KEY,
            action_hash TEXT NOT NULL,
            action_json TEXT NOT NULL,
            approver_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            consumed INTEGER NOT NULL DEFAULT 0,
            approval_mac TEXT
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

        CREATE TABLE IF NOT EXISTS organizations (
            org_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memberships (
            org_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (org_id, actor_id)
        );

        CREATE TABLE IF NOT EXISTS documents (
            document_id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            owner_actor_id TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            media_type TEXT NOT NULL,
            extension TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            original_path TEXT NOT NULL,
            derivative_path TEXT,
            original_sha256 TEXT NOT NULL,
            derivative_sha256 TEXT,
            mode TEXT NOT NULL,
            status TEXT NOT NULL,
            review_required INTEGER NOT NULL,
            findings_json TEXT NOT NULL,
            scanner_status TEXT NOT NULL,
            extraction_status TEXT NOT NULL,
            processing_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            deletion_status TEXT NOT NULL DEFAULT 'active',
            deletion_operation_id TEXT,
            deletion_requested_at TEXT,
            deletion_completed_at TEXT,
            receipt_json TEXT,
            receipt_signature TEXT,
            receipt_key_id TEXT
        );

        CREATE INDEX IF NOT EXISTS documents_org_idx ON documents(org_id, created_at);
        """
    )
    approval_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(approvals)")
    }
    if "approval_mac" not in approval_columns:
        # Existing demo databases are upgraded conservatively.  Legacy rows
        # without a MAC are rejected by the gateway and must be re-approved.
        connection.execute("ALTER TABLE approvals ADD COLUMN approval_mac TEXT")
    patient_columns = {row[1] for row in connection.execute("PRAGMA table_info(patients)")}
    if "org_id" not in patient_columns:
        connection.execute("ALTER TABLE patients ADD COLUMN org_id TEXT")
    document_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(documents)")
    }
    document_migrations = {
        "deletion_status": "TEXT NOT NULL DEFAULT 'active'",
        "deletion_operation_id": "TEXT",
        "deletion_requested_at": "TEXT",
        "deletion_completed_at": "TEXT",
        "receipt_json": "TEXT",
        "receipt_signature": "TEXT",
        "receipt_key_id": "TEXT",
    }
    for column, definition in document_migrations.items():
        if column not in document_columns:
            connection.execute(f"ALTER TABLE documents ADD COLUMN {column} {definition}")
    connection.commit()


def seed_data(connection: sqlite3.Connection) -> None:
    """Insert obviously fake demo records without overwriting team changes."""

    connection.executemany(
        "INSERT OR IGNORE INTO actors(actor_id, role) VALUES (?, ?)",
        [
            ("clinician_1", "clinician"),
            ("clinician_2", "clinician"),
            ("nurse_1", "nurse"),
            ("agent_1", "agent"),
            ("pharmacist_1", "pharmacist"),
            ("service_account_1", "service_account"),
            ("privacy_1", "privacy_officer"),
            ("researcher_1", "researcher"),
            ("auditor_1", "read_only_auditor"),
            ("org_admin_1", "org_admin"),
            ("platform_admin_1", "platform_admin"),
        ],
    )
    connection.executemany(
        "INSERT OR IGNORE INTO patients(patient_id, name_synthetic, org_id) VALUES (?, ?, ?)",
        [
            ("P-101", "Synthetic Patient Echo", "ORG-DEMO"),
            ("P-102", "Synthetic Patient Foxtrot", "ORG-DEMO"),
            ("P-104", "Synthetic Patient Alpha", "ORG-DEMO"),
            ("P-205", "Synthetic Patient Beta", "ORG-DEMO"),
            ("P-318", "Synthetic Patient Gamma", "ORG-DEMO"),
            ("P-422", "Synthetic Patient Delta", "ORG-DEMO"),
        ],
    )
    connection.execute(
        "UPDATE patients SET org_id = 'ORG-DEMO' WHERE org_id IS NULL OR org_id = ''"
    )
    # Keep apply_order as the only order-table writer, including for demo data.
    from guard.models import ProtectedAction
    from guard.policy import PINNED_DESTINATIONS, TOOL_BASELINE_FINGERPRINTS
    from .backend import _GATEWAY_EXECUTION_TOKEN, apply_order

    existing_order = connection.execute(
        "SELECT 1 FROM orders WHERE order_id = ?",
        ("ORD-DEMO-001",),
    ).fetchone()
    if existing_order is None:
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
            _gateway_token=_GATEWAY_EXECUTION_TOKEN,
        )
    additional_demo_orders = [
        ProtectedAction(
            patient_id="P-205",
            medication_id="MED-B",
            dose="500",
            units="mg",
            route="oral",
            frequency="twice daily",
            duration="14 days",
            order_id="ORD-DEMO-002",
        ),
        ProtectedAction(
            patient_id="P-318",
            medication_id="MED-C",
            dose="250",
            units="mg",
            route="oral",
            frequency="three times daily",
            duration="10 days",
            order_id="ORD-DEMO-003",
        ),
        ProtectedAction(
            patient_id="P-422",
            medication_id="MED-D",
            dose="10",
            units="mg",
            route="subcutaneous",
            frequency="daily",
            duration="30 days",
            order_id="ORD-DEMO-004",
        ),
    ]
    for demo_action in additional_demo_orders:
        if connection.execute(
            "SELECT 1 FROM orders WHERE order_id = ?",
            (demo_action.order_id,),
        ).fetchone() is None:
            apply_order(
                demo_action,
                connection=connection,
                _gateway_token=_GATEWAY_EXECUTION_TOKEN,
            )
    connection.execute(
        """
        INSERT OR IGNORE INTO tool_baseline(
            tool_name, fingerprint, allowed_destination
        ) VALUES (?, ?, ?)
        """,
        (
            "update_order",
            TOOL_BASELINE_FINGERPRINTS["update_order"],
            PINNED_DESTINATIONS["update_order"],
        ),
    )
    connection.executemany(
        "INSERT OR IGNORE INTO organizations(org_id, name, created_at) VALUES (?, ?, ?)",
        [
            ("ORG-DEMO", "Synthetic Demo Organization", "2026-01-01T00:00:00Z"),
            ("ORG-SECOND", "Synthetic Partner Organization", "2026-01-01T00:00:00Z"),
        ],
    )
    connection.executemany(
        "INSERT OR IGNORE INTO memberships(org_id, actor_id, role, active) VALUES (?, ?, ?, 1)",
        [
            ("ORG-DEMO", "clinician_2", "clinician"),
            ("ORG-DEMO", "clinician_1", "clinician"),
            ("ORG-DEMO", "nurse_1", "nurse"),
            ("ORG-DEMO", "agent_1", "agent"),
            ("ORG-DEMO", "pharmacist_1", "pharmacist"),
            ("ORG-DEMO", "service_account_1", "service_account"),
            ("ORG-DEMO", "privacy_1", "privacy_officer"),
            ("ORG-DEMO", "researcher_1", "researcher"),
            ("ORG-DEMO", "auditor_1", "read_only_auditor"),
            ("ORG-DEMO", "org_admin_1", "org_admin"),
            ("ORG-DEMO", "platform_admin_1", "platform_admin"),
        ],
    )
    connection.commit()


def initialize_db(db_path: PathLike = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open, create, and seed a synthetic MediShield database."""

    connection = get_connection(db_path)
    init_db(connection)
    seed_data(connection)
    return connection
