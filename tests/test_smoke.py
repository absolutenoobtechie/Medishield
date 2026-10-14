"""Import-only smoke tests for the scaffold."""

import importlib


MODULES = [
    "guard.models",
    "guard.intent",
    "guard.gateway",
    "guard.policy",
    "guard.audit",
    "server.db",
    "server.backend",
    "server.mcp_server",
    "dashboard.app",
]


def test_modules_import():
    for module_name in MODULES:
        assert importlib.import_module(module_name) is not None
