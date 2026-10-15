"""Import and configuration smoke tests for the runtime prototype."""

import importlib


MODULES = [
    "guard.models",
    "guard.intent",
    "guard.gateway",
    "guard.policy",
    "guard.audit",
    "guard.sentinel",
    "guard.forensics",
    "server.db",
    "server.backend",
    "server.mcp_server",
    "dashboard.app",
]


def test_modules_import():
    for module_name in MODULES:
        assert importlib.import_module(module_name) is not None


def test_runtime_modules_share_the_repository_database_default():
    from guard import audit, gateway
    from server import backend, mcp_server
    from server.db import DEFAULT_DB_PATH

    assert DEFAULT_DB_PATH.is_absolute()
    assert backend.DATABASE_PATH == DEFAULT_DB_PATH
    assert audit.DATABASE_PATH == DEFAULT_DB_PATH
    assert gateway.DEFAULT_DB_PATH == DEFAULT_DB_PATH
    assert mcp_server.DATABASE_PATH == DEFAULT_DB_PATH
