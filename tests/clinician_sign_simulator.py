#!/usr/bin/env python3
# Eclipse Meridian MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# TEST FIXTURE ONLY: clinician-sign simulator (spec 12.1 P0-5 bench equipment).

"""Clinician-sign SIMULATOR — bench equipment, tests/ only.

This module is NOT part of the shipped product. It lives under
tests/ because the shipped engine/server/Tools must contain NO
signing capability in any product file (spec 12.1 P0-5 + C3:
the simulator "ships in no product surface"). It models the
treating clinician's own act in the system of record: signs the
exact fingerprint or refuses NOTE_FINGERPRINT_MISMATCH; the
signed state is immutable.

Eclipse Meridian — governed telehealth operations —
jurisdiction-gated encounters, signed-note integrity, PHI access
evidence. Not a healthcare provider.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import meridian_engine as E  # noqa: E402


def clinician_sign(state, draft_id, fingerprint, signer_id):
    """Fixture actor: sign the exact draft fingerprint into the
    record state, or raise the named Refusal. Test code only —
    no product file imports or references this function."""
    draft = state["drafts"].get(draft_id)
    if draft is None:
        raise E.Refusal("DRAFT_NOT_FOUND", f"no draft {draft_id}")
    if E.note_fingerprint(draft) != fingerprint:
        raise E.Refusal("NOTE_FINGERPRINT_MISMATCH",
                        "fingerprint at sign instant differs from "
                        "the requested fingerprint; sign does not "
                        "land")
    note_id = E._tid("NOTE")
    signed = {"note_id": note_id, "draft_id": draft_id,
              "encounter_id": draft["encounter_id"],
              "author_agent_id": draft["author_agent_id"],
              "signed_fingerprint": fingerprint,
              "signer_clinician_id": signer_id,
              "signed_at": E.now_iso(), "version": draft["version"],
              "content_snapshot": draft["content"],
              "supersedes_ref": draft.get("addendum_of")}
    state["signed_notes"][note_id] = signed
    if draft.get("addendum_of") in state["signed_notes"]:
        state["signed_notes"][draft["addendum_of"]][
            "superseded_by"] = note_id
    draft["signed"] = True
    draft["state"] = "SIGNED"
    draft["signed_note_id"] = note_id
    pack = state["packs"].get(draft["encounter_id"])
    if pack is not None:
        pack["pin_statement"] = {
            "signed_fingerprint": fingerprint, "note_id": note_id}
    return signed


# Eclipse Meridian MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
