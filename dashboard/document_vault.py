"""Streamlit adapter for the synthetic, tenant-scoped document vault."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import streamlit as st

from privacy.auth import AuthorizationError, authenticate_local
from privacy.vault import (
    DocumentIntegrityError,
    DocumentValidationError,
    StorageConfigurationError,
    list_documents,
    retrieve_document,
    review_document,
    upload_document,
    verify_document_integrity,
)
from server.db import get_connection, init_db, seed_data


_ACTORS = {
    "org_admin_1": "Organization admin",
    "clinician_1": "Clinician",
    "privacy_1": "Privacy officer",
    "researcher_1": "Researcher",
    "auditor_1": "Read-only auditor",
}


def render_document_vault(*, db_path: Path, storage_root: Path) -> None:
    """Render upload, privacy-review, retrieval, and integrity controls.

    The identity selector is explicitly a local synthetic-demo identity.  It
    does not pretend to be password authentication; every operation still
    re-checks the selected actor's server-side membership and role.
    """

    st.title("Secure Document Vault")
    st.caption(
        "Synthetic local workspace. The identity selector is demo-only; backend membership checks remain authoritative."
    )
    connection = get_connection(db_path)
    try:
        init_db(connection)
        seed_data(connection)
        actor_id = st.selectbox("Local demo identity", list(_ACTORS), format_func=lambda value: f"{_ACTORS[value]} ({value})")
        try:
            user = authenticate_local(connection, actor_id, "ORG-DEMO")
        except AuthorizationError as exc:
            st.error(str(exc))
            return

        st.info(f"Organization: {user.org_id} • Role: {user.role}. All data is synthetic.")
        upload_tab, review_tab, retrieve_tab = st.tabs(["Upload", "Privacy review", "Retrieve / verify"])

        with upload_tab:
            uploaded = st.file_uploader("Upload TXT, PDF, PNG, or JPEG", type=["txt", "pdf", "png", "jpg", "jpeg"])
            mode = st.selectbox("Processing mode", ["redaction", "pseudonymization", "detection"])
            if st.button("Validate, de-identify, and encrypt", type="primary", disabled=uploaded is None):
                try:
                    result = upload_document(
                        connection,
                        user,
                        uploaded.name,
                        uploaded.getvalue(),
                        mode=mode,
                        storage_root=storage_root,
                    )
                    st.success(f"Stored {result['document_id']} as encrypted pending-review data.")
                    st.json(result["report"])
                except (AuthorizationError, DocumentValidationError, StorageConfigurationError) as exc:
                    st.error(f"Upload blocked: {exc}")

        documents = list_documents(connection, user)
        with review_tab:
            st.write("Documents remain pending until a privacy officer or organization admin approves them.")
            if not documents:
                st.info("No documents in this organization.")
            for document in documents:
                with st.container(border=True):
                    st.write(f"{document['document_id']} • {document['media_type']} • {document['status']}")
                    st.caption(f"Review required: {document['review_required']} • Scanner: {document['scanner_status']}")
                    st.json(document["report"])
                    if user.role in {"privacy_officer", "org_admin"} and document["status"] == "pending_review":
                        if st.button("Approve synthetic document", key=f"approve-{document['document_id']}"):
                            try:
                                review_document(
                                    connection,
                                    user,
                                    document["document_id"],
                                    "approve",
                                    storage_root=storage_root,
                                )
                                st.rerun()
                            except (AuthorizationError, LookupError) as exc:
                                st.error(f"Review failed: {exc}")

        with retrieve_tab:
            if not documents:
                st.info("Upload a document first.")
            else:
                selected_id = st.selectbox("Document", [item["document_id"] for item in documents])
                variant = st.selectbox("Variant", ["derivative", "original"])
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Verify encrypted content"):
                        try:
                            st.json(verify_document_integrity(connection, user, selected_id, storage_root=storage_root))
                        except (AuthorizationError, LookupError) as exc:
                            st.error(f"Verification blocked: {exc}")
                with col2:
                    retrieval_key = f"vault_retrieved_{selected_id}_{variant}"
                    if st.button("Retrieve approved content"):
                        try:
                            content = retrieve_document(
                                connection,
                                user,
                                selected_id,
                                variant=variant,
                                storage_root=storage_root,
                            )
                            st.session_state[retrieval_key] = content
                            st.success("Gateway-authorized retrieval completed after authentication and hash verification.")
                        except (AuthorizationError, DocumentIntegrityError, DocumentValidationError, StorageConfigurationError) as exc:
                            st.session_state.pop(retrieval_key, None)
                            st.error(f"Retrieval blocked: {exc}")

                    if retrieval_key in st.session_state:
                        st.download_button(
                            "Download verified content",
                            data=st.session_state[retrieval_key],
                            file_name=f"{selected_id}.{variant}.bin",
                            mime="application/octet-stream",
                        )
    finally:
        connection.close()
