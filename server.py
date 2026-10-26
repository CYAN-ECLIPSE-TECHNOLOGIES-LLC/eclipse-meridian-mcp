#!/usr/bin/env python3
# Eclipse Meridian MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Meridian Core MCP server (stdio): the 19 spec tools, nothing else.

"""Eclipse Meridian — governed telehealth operations —
jurisdiction-gated encounters, signed-note integrity, PHI access
evidence. Not a healthcare provider.

Exactly 19 tools per spec section 6.1. PRODUCT LAW (spec 6.2):
there is NO note_finalize / sign-off-class tool in this surface —
signature is the treating clinician's act in the system of
record; the agent surface ends at note_sign_request. No
prescribing surface exists in any phase. P0 is synthetic-only.

Transport: MCP over stdio (newline-delimited JSON-RPC 2.0),
stdlib only. State: $ECLIPSE_MERIDIAN_STATE or ./data/state.json.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import meridian_engine as engine  # noqa: E402
from meridian_engine import ToolError  # noqa: E402

S = {"type": "string"}
O = {"type": "object"}
A = {"type": "array"}
B = {"type": "boolean"}

TOOLS = {
    # -- Mandate admin (2) — customer-admin channel only
    "mandate_upsert": (
        engine.mandate_upsert,
        "Upsert a Herald-signed mandate (agent x practice x "
        "purposes x field classes x visit types x expiry). "
        "CUSTOMER-ADMIN CHANNEL ONLY: agents cannot amend "
        "mandates, including on the owner's in-session word.",
        {"channel": S, "actor": S, "payload": O, "now": S},
        ["channel", "payload"]),
    "mandate_get": (
        engine.mandate_get,
        "Read a mandate's terms exactly as signed (read-only).",
        {"mandate_ref": S, "now": S}, ["mandate_ref"]),
    # -- Jurisdiction (3)
    "license_verify_at_encounter": (
        engine.license_verify_at_encounter,
        "Verify, AT ENCOUNTER TIME and never from cache, that the "
        "treating clinician's license/privilege covers the "
        "patient's attested state. Every answer carries source + "
        "as-of; no fact = LICENSE_STATE_UNVERIFIED, fail closed.",
        {"clinician_id": S, "patient_state": S,
         "profession_class": S, "visit_type": S,
         "encounter_ref": S, "mandate_ref": S, "now": S},
        ["clinician_id", "patient_state", "profession_class"]),
    "consent_set_required": (
        engine.consent_set_required,
        "The consent artifact set a counsel-signed policy pack "
        "requires for jurisdiction x visit type; pack version is "
        "stamped on the output.",
        {"jurisdiction": S, "visit_type": S,
         "recording_requested": B, "now": S},
        ["jurisdiction", "visit_type"]),
    "encounter_gate_check": (
        engine.encounter_gate_check,
        "Dry-run Lock A gate (licensure x consent set x mandate) "
        "against an encounter draft. confers no authority and "
        "changes no state.",
        {"encounter_draft": O, "now": S}, ["encounter_draft"]),
    # -- Encounter flow (3)
    "encounter_schedule": (
        engine.encounter_schedule,
        "Schedule an encounter ONLY on a gate pass at schedule "
        "time (booking-time attestation). A failed gate books "
        "nothing; no book-now-verify-later state exists.",
        {"encounter_draft": O, "now": S}, ["encounter_draft"]),
    "encounter_start_gate": (
        engine.encounter_start_gate,
        "Start authorization: fresh location attestation + FULL "
        "gate re-run (A1+A2+A3). A location change since booking "
        "re-runs the gate; a booking pass confers zero authority.",
        {"encounter_ref": S, "patient_state": S,
         "attestation_source": S, "consent_artifacts": A,
         "now": S},
        ["encounter_ref", "patient_state"]),
    "encounter_pack_get": (
        engine.encounter_pack_get,
        "The sealed encounter pack: both gate verdicts, consent "
        "events, access-record refs, pack versions, and the pin "
        "statement (NO_PIN_RECORD where no signed note exists).",
        {"encounter_ref": S}, ["encounter_ref"]),
    # -- Intake administration (2) — read-only in P0
    "intake_template_get": (
        engine.intake_template_get,
        "The practice-configured intake template for a visit type "
        "(administrative fields only).",
        {"practice_id": S, "visit_type": S},
        ["practice_id", "visit_type"]),
    "intake_status_get": (
        engine.intake_status_get,
        "Intake completion state per section, source-labeled. No "
        "inference, no clinical answers, no eligibility or "
        "coverage determination.",
        {"intake_ref": S, "purpose": S, "mandate_ref": S,
         "agent_id": S, "now": S},
        ["intake_ref", "purpose", "mandate_ref"]),
    # -- Documentation flow (5) — the chain ends at the clinician
    "note_draft_create": (
        engine.note_draft_create,
        "Create/edit a draft in the DRAFT STORE, outside the "
        "record. Standing status UNSIGNED_DRAFT_NOT_RECORD; no "
        "chart read ever returns a draft.",
        {"encounter_ref": S, "content": S, "drafting_agent_id": S,
         "edit_of_draft_id": S},
        ["encounter_ref", "drafting_agent_id"]),
    "note_fingerprint_get": (
        engine.note_fingerprint_get,
        "Canonical fingerprint (SHA-256, meridian-canon-v1) of "
        "the exact current draft state.",
        {"draft_ref": S}, ["draft_ref"]),
    "note_sign_request": (
        engine.note_sign_request,
        "Route the EXACT fingerprint to the treating clinician "
        "for signature in the system of record. This tool signs "
        "NOTHING; no agent tool signs or finalizes a note.",
        {"draft_ref": S, "fingerprint": S,
         "treating_clinician_ref": S},
        ["draft_ref", "fingerprint", "treating_clinician_ref"]),
    "note_signed_status_get": (
        engine.note_signed_status_get,
        "UNSIGNED_DRAFT / SIGNED (signed fingerprint + signer + "
        "instant) / addendum-chain state for a draft or note ref.",
        {"note_ref": S}, ["note_ref"]),
    "note_addendum_create": (
        engine.note_addendum_create,
        "The ONLY post-signature change path: a new draft version "
        "chained to the signed original, citing its fingerprint. "
        "The original remains served exactly as signed.",
        {"signed_note_ref": S, "content": S,
         "drafting_agent_id": S},
        ["signed_note_ref", "content", "drafting_agent_id"]),
    # -- PHI reads + access evidence (4)
    "patient_context_get": (
        engine.patient_context_get,
        "Projected patient context: ONLY the field classes the "
        "acting mandate grants for the declared purpose, "
        "projected server-side before serialization. Every call, "
        "granted or refused, seals a 164.312(b)-shaped record.",
        {"patient_ref": S, "purpose": S, "mandate_ref": S,
         "requested_classes": A, "agent_id": S, "now": S},
        ["patient_ref", "purpose", "mandate_ref"]),
    "appointment_get": (
        engine.appointment_get,
        "Appointment record within mandate-granted field classes "
        "for the declared purpose; sealed either way.",
        {"appointment_ref": S, "purpose": S, "mandate_ref": S,
         "requested_classes": A, "now": S},
        ["appointment_ref", "purpose", "mandate_ref"]),
    "access_pack_get": (
        engine.access_pack_get,
        "Practice-held access pack: hash-chained records exported "
        "mapped to FHIR AuditEvent + Provenance. Audit reads "
        "declare purpose AUDIT_REVIEW.",
        {"practice_id": S, "mandate_ref": S, "purpose": S,
         "patient_ref": S, "now": S},
        ["practice_id", "mandate_ref", "purpose"]),
    "access_pack_verify": (
        engine.access_pack_verify,
        "Offline verification of an exported access pack: chain "
        "integrity + interval completeness. Gaps are findings, "
        "never silently passed.",
        {"access_pack": O, "expected_interval": O},
        ["access_pack"]),
}


def tool_list():
    return [{"name": name, "description": description,
             "inputSchema": {"type": "object", "properties": props,
                             "required": required}}
            for name, (_, description, props, required)
            in TOOLS.items()]


def handle(req: dict):
    method, rid = req.get("method", ""), req.get("id")
    if method == "initialize":
        init_params = req.get("params")
        if not isinstance(init_params, dict):
            init_params = {}
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": init_params.get(
                "protocolVersion", "2025-03-26"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "eclipse-meridian",
                           "title": engine.DESCRIPTOR,
                           "version": engine.VERSION}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"tools": tool_list()}}
    if method == "tools/call":
        params = req.get("params")
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602,
                "message": "params must be an object"}}
        name = params.get("name")
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602,
                "message": "arguments must be an object"}}
        if name not in TOOLS:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602,
                "message": f"unknown tool {name}: Meridian ships "
                           f"exactly 19 tools; no finalize/sign "
                           f"tool exists by product law (spec 6.2)"}}
        state = engine.load_state()
        try:
            engine.deep_key_scan(args)
            out = TOOLS[name][0](state, args)
            engine.save_state(state)
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": json.dumps(out, indent=1)}],
                "isError": not out.get("ok", False)}}
        except ToolError as exc:
            engine.save_state(state)
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": json.dumps(
                                 {"ok": False, "error": str(exc)})}],
                "isError": True}}
    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32601, "message": f"method not found: {method}"}}
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req_id = None
        try:
            req = json.loads(line)
            if isinstance(req, dict):
                req_id = req.get("id")
            response = handle(req)
        except Exception as exc:  # never crash the transport;
            # the response ALWAYS carries the request id when the
            # request carried one — an id-less error is a defect
            response = {"jsonrpc": "2.0", "id": req_id, "error": {
                "code": -32603, "message": str(exc)}}
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

# Eclipse Meridian MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
