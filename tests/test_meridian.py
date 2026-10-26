# Eclipse Meridian MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Test suite: distinguishing tests DT-1..DT-5, hostile suite, locks A/B/C, Bridge BAA gate, standalone tools.

"""Eclipse Meridian test suite (synthetic data only).

Covers spec section 13 distinguishing tests, the hostile-suite
shapes buildable at P0, fingerprint vectors, ledger chaining, and
the builder self-checks (finalize-verb surface sweep, gate re-run
on location change, BAA_REQUIRED, restricted-class default
exclusion, no live-network code paths).
"""
import copy
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "tools"))
import meridian_engine as E  # noqa: E402
import clinician_sign_simulator as SIM  # noqa: E402
import server  # noqa: E402
import encounter_gate  # noqa: E402
import note_pin_verifier  # noqa: E402
import access_ledger_verifier  # noqa: E402
import policy_pack_workbench  # noqa: E402

T0 = "2026-10-25T10:00:00Z"
T1 = "2026-10-25T13:00:00Z"  # after CLIN-LAPSE lapses_at (12:00)
PASS = []
FAIL = []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print(f"FAIL: {name} {extra}")


def mandate_payload(**over):
    payload = {"agent_id": "agent-sched", "practice_id": "PRAC-SYN-1",
               "purpose_set": ["SCHEDULING"],
               "field_classes": ["IDENTITY_CONTACT", "APPOINTMENT"],
               "visit_types": ["VIDEO_FOLLOWUP", "VIDEO_INITIAL",
                               "AUDIO_FOLLOWUP"],
               "expiry": "2027-01-01T00:00:00Z"}
    payload.update(over)
    return payload


def upsert(state, payload, channel="customer_admin"):
    signed = E.sign_mandate_payload(copy.deepcopy(payload))
    return E.mandate_upsert(state, {"channel": channel,
                                    "payload": signed, "now": T0})


def draft_enc(clinician="CLIN-CA-ONLY", state_att="SYN-CA",
              mandate_ref=None, consents=("telehealth",),
              recording=False, participants=()):
    artifacts = [{"consent_type": c, "participant_ref": "PAT-SYN-001",
                  "method": "verbal", "captured_at": T0}
                 for c in consents]
    if recording:
        artifacts += [{"consent_type": "recording",
                       "participant_ref": p, "method": "verbal",
                       "captured_at": T0} for p in participants]
    return {"clinician_id": clinician, "patient_ref": "PAT-SYN-001",
            "patient_state": state_att,
            "visit_type": "VIDEO_FOLLOWUP",
            "profession_class": "MD", "mandate_ref": mandate_ref,
            "practice_id": "PRAC-SYN-1",
            "consent_artifacts": artifacts,
            "participants": list(participants),
            "recording_requested": recording}


def fresh_with_mandate(**over):
    state = E.fresh_state()
    out = upsert(state, mandate_payload(**over))
    assert out["ok"], out
    return state, out["data"]["mandate_ref"]


# ------------------------------------------------------------ surface
def test_surface_no_finalize():
    names = [t["name"] for t in server.tool_list()]
    check("surface: exactly 19 tools", len(names) == 19, str(names))
    bad = [n for n in names if re.search(
        r"final|sign_off|signoff|approve_note|prescri|diagnos|"
        r"triage|override|bypass", n)]
    check("H-5/self-check(a): ZERO finalize/sign-off-class tools",
          bad == [], str(bad))
    expected = {"mandate_upsert", "mandate_get",
                "license_verify_at_encounter",
                "consent_set_required", "encounter_gate_check",
                "encounter_schedule", "encounter_start_gate",
                "encounter_pack_get", "intake_template_get",
                "intake_status_get", "note_draft_create",
                "note_fingerprint_get", "note_sign_request",
                "note_signed_status_get", "note_addendum_create",
                "patient_context_get", "appointment_get",
                "access_pack_get", "access_pack_verify"}
    check("surface: names match spec 6.1 exactly",
          set(names) == expected)


def test_guards():
    for fn, args, frag in [
            (E.coerce_int_param, (True, "x"), "boolean"),
            (E.coerce_int_param, ("abc", "x"), "must be an integer"),
            (E.parse_time, ("2026-10-25T10:00:00",), "NO_OFFSET"),
            (E.require_ref_param, ({"a": 1}, "ref"), "REF_TYPE")]:
        try:
            fn(*args)
            check(f"guard {frag}", False)
        except E.ToolError as exc:
            check(f"guard {frag}", frag in str(exc))
    try:
        E.deep_key_scan({"a": {"b": [{"note_finalize": 1}]}})
        check("deep-key scan catches nested finalize", False)
    except E.ToolError as exc:
        check("deep-key scan catches nested finalize",
              "DENIED_KEY" in str(exc))


# ------------------------------------------------------------ mandates
def test_mandates():
    state = E.fresh_state()
    out = upsert(state, mandate_payload())
    check("mandate: signed admin upsert ok", out["ok"])
    ref = out["data"]["mandate_ref"]
    got = E.mandate_get(state, {"mandate_ref": ref, "now": T0})
    check("mandate: get returns signed terms",
          got["ok"] and got["data"]["mandate"]["agent_id"]
          == "agent-sched")
    # H-4: agent channel cannot amend, even well-formed + signed
    out = E.mandate_upsert(state, {
        "channel": "agent_session",
        "payload": E.sign_mandate_payload(mandate_payload()),
        "now": T0})
    check("H-4: agent-channel upsert refused",
          not out["ok"] and out["refusal_class"]
          == "MANDATE_SIGNATURE_INVALID")
    check("H-4: attempt logged", len(state["admin_log"]) == 1)
    bad = mandate_payload()
    signed = E.sign_mandate_payload(bad)
    signed["field_classes"] = ["FULL_CHART"]  # tamper post-signing
    out = E.mandate_upsert(state, {"channel": "customer_admin",
                                   "payload": signed, "now": T0})
    check("mandate: tampered signature refused",
          out["refusal_class"] == "MANDATE_SIGNATURE_INVALID")
    out = upsert(state, mandate_payload(field_classes=[
        "IDENTITY_CONTACT", "FULL_CHART"]))
    check("mandate: FULL_CHART on SCHEDULING not grantable",
          out["refusal_class"] == "MANDATE_TERM_NOT_GRANTABLE")
    out = upsert(state, mandate_payload(
        purpose_set=["DOCUMENTATION"],
        field_classes=["PART2_SUD"]))
    check("mandate: Part 2 class never grantable (default EXCLUDED)",
          out["refusal_class"] == "MANDATE_TERM_NOT_GRANTABLE")
    out = upsert(state, mandate_payload(
        purpose_set=["DOCUMENTATION"],
        field_classes=["MINOR_RESTRICTED"]))
    check("mandate: minor-restricted never grantable",
          out["refusal_class"] == "MANDATE_TERM_NOT_GRANTABLE")
    out = upsert(state, mandate_payload(
        expiry="2026-01-01T00:00:00Z"))
    ref2 = out["data"]["mandate_ref"]
    got = E.mandate_get(state, {"mandate_ref": ref2, "now": T0})
    check("mandate: expired reads MANDATE_EXPIRED",
          got["refusal_class"] == "MANDATE_EXPIRED")


# ------------------------------------------------------------ Lock A
def test_lock_a():
    state, ref = fresh_with_mandate()
    # DT-1: NY patient x CA-only clinician -> refused pre-booking
    out = E.encounter_schedule(state, {
        "encounter_draft": draft_enc(state_att="SYN-NY",
                                     mandate_ref=ref), "now": T0})
    check("DT-1: cross-state schedule refused JURISDICTION_MISMATCH",
          out["refusal_class"] == "JURISDICTION_MISMATCH")
    check("DT-1: nothing booked", state["encounters"] == {})
    check("DT-1: cited fact carries roster source",
          out["cited_fact"] and "SYNTHETIC-ROSTER" in
          out["cited_fact"]["source"])
    # consent set incomplete (SYN-CA VIDEO_INITIAL needs ai_use too;
    # here followup needs telehealth only, so use missing set)
    out = E.encounter_gate_check(state, {
        "encounter_draft": draft_enc(mandate_ref=ref, consents=()),
        "now": T0})
    check("gate: missing consent -> CONSENT_SET_INCOMPLETE",
          out["refusal_class"] == "CONSENT_SET_INCOMPLETE")
    # happy path schedule
    out = E.encounter_schedule(state, {
        "encounter_draft": draft_enc(mandate_ref=ref), "now": T0})
    check("gate: matching state+consent schedules", out["ok"])
    enc = out["data"]["encounter_id"]
    # DT-4 / self-check(b): location change booking->start re-runs
    out = E.encounter_start_gate(state, {
        "encounter_ref": enc, "patient_state": "SYN-NY", "now": T0})
    check("DT-4: start gate re-runs, refuses JURISDICTION_MISMATCH",
          out["refusal_class"] == "JURISDICTION_MISMATCH")
    check("DT-4: location_changed flagged",
          out["data"]["location_changed"] is True)
    check("DT-4: encounter NOT started",
          state["encounters"][enc]["state"] == "SCHEDULED")
    pack = E.encounter_pack_get(state, {"encounter_ref": enc})
    check("pack: both gate verdicts recorded",
          len(pack["data"]["encounter_pack"]["gate_verdicts"]) == 2)
    check("pack: NO_PIN_RECORD stated",
          pack["data"]["encounter_pack"]["pin_statement"]
          == "NO_PIN_RECORD")
    # same-state start passes
    out = E.encounter_start_gate(state, {
        "encounter_ref": enc, "patient_state": "SYN-CA", "now": T0})
    check("gate: same-state start passes", out["ok"] and
          state["encounters"][enc]["state"] == "STARTED")
    # DT-5: recording requested, patient's recording artifact
    # missing -> recording cannot start; schedule refuses
    state2, ref2 = fresh_with_mandate()
    d5 = draft_enc(mandate_ref=ref2, recording=False,
                   participants=["PAT-SYN-001"],
                   consents=("telehealth",))
    d5["recording_requested"] = True  # requested, never consented
    out = E.encounter_schedule(state2, {
        "encounter_draft": d5, "now": T0})
    check("DT-5: unconsented participant recording refused at "
          "schedule", out["refusal_class"]
          == "RECORDING_CONSENT_MISSING")
    out = E.encounter_gate_check(state2, {
        "encounter_draft": draft_enc(
            mandate_ref=ref2, recording=True,
            participants=["PAT-SYN-001", "CLIN-CA-ONLY"],
            consents=("telehealth",)), "now": T0})
    # only patient got a recording artifact via participants loop:
    # draft_enc adds artifacts for all listed participants, so
    # rebuild manually with one missing
    d = draft_enc(mandate_ref=ref2, recording=True,
                  participants=["PAT-SYN-001"], consents=("telehealth",))
    d["participants"] = ["PAT-SYN-001", "INTERPRETER-1"]
    out = E.encounter_gate_check(state2, {"encounter_draft": d,
                                          "now": T0})
    check("DT-5/H-17: third participant unaccounted -> "
          "RECORDING_CONSENT_MISSING",
          out["refusal_class"] == "RECORDING_CONSENT_MISSING")
    # H-2: license lapses between booking and start
    state3, ref3 = fresh_with_mandate()
    out = E.encounter_schedule(state3, {
        "encounter_draft": draft_enc(clinician="CLIN-LAPSE",
                                     mandate_ref=ref3), "now": T0})
    enc3 = out["data"]["encounter_id"]
    out = E.encounter_start_gate(state3, {
        "encounter_ref": enc3, "patient_state": "SYN-CA", "now": T1})
    check("H-2: lapsed-at-start license refused",
          out["refusal_class"] == "JURISDICTION_MISMATCH")
    # H-3: feed returns no fact -> fail closed
    out = E.license_verify_at_encounter(state3, {
        "clinician_id": "CLIN-FEED-DOWN", "patient_state": "SYN-CA",
        "profession_class": "MD", "now": T0})
    check("H-3: no license fact -> LICENSE_STATE_UNVERIFIED",
          out["refusal_class"] == "LICENSE_STATE_UNVERIFIED")
    # H-12: mandate expires between booking and start
    state4 = E.fresh_state()
    out = upsert(state4, mandate_payload(
        expiry="2026-10-25T11:00:00Z"))
    ref4 = out["data"]["mandate_ref"]
    out = E.encounter_schedule(state4, {
        "encounter_draft": draft_enc(mandate_ref=ref4), "now": T0})
    enc4 = out["data"]["encounter_id"]
    out = E.encounter_start_gate(state4, {
        "encounter_ref": enc4, "patient_state": "SYN-CA", "now": T1})
    check("H-12: expired mandate at start -> MANDATE_EXPIRED",
          out["refusal_class"] == "MANDATE_EXPIRED")
    # H-11: unsigned + stale packs
    out = E.consent_set_required(state, {
        "jurisdiction": "SYN-WA", "visit_type": "VIDEO_FOLLOWUP",
        "now": T0})
    check("H-11: unsigned pack -> POLICY_PACK_UNSIGNED",
          out["refusal_class"] == "POLICY_PACK_UNSIGNED")
    out = E.consent_set_required(state, {
        "jurisdiction": "SYN-TX", "visit_type": "VIDEO_FOLLOWUP",
        "now": T1})
    check("H-11: pack past effective interval -> POLICY_PACK_STALE",
          out["refusal_class"] == "POLICY_PACK_STALE")
    out = E.consent_set_required(state, {
        "jurisdiction": "SYN-XX", "visit_type": "VIDEO_FOLLOWUP",
        "now": T0})
    check("pack: unknown jurisdiction -> JURISDICTION_NOT_IN_PACK",
          out["refusal_class"] == "JURISDICTION_NOT_IN_PACK")
    out = E.consent_set_required(state, {
        "jurisdiction": "SYN-CA", "visit_type": "VIDEO_INITIAL",
        "now": T0})
    check("pack: consent set served from DATA pack w/ version",
          out["ok"] and out["data"]["required_consents"]
          == ["telehealth", "ai_use"]
          and out["policy_pack_version"] == "1.2.0")
    # dry-run purity
    state5, ref5 = fresh_with_mandate()
    for _ in range(3):
        E.encounter_gate_check(state5, {
            "encounter_draft": draft_enc(mandate_ref=ref5),
            "now": T0})
    check("gate dry-run purity: zero bookings after N checks",
          state5["encounters"] == {})
    out = E.encounter_gate_check(state5, {
        "encounter_draft": draft_enc(
            mandate_ref=ref5, visit_types=None) if False else
        {**draft_enc(mandate_ref=ref5), "visit_type": "HOME_VISIT"},
        "now": T0})
    check("gate: visit outside mandate/pack refused",
          not out["ok"])


# ------------------------------------------------------------ Lock B
def _started_encounter(state, ref):
    out = E.encounter_schedule(state, {
        "encounter_draft": draft_enc(mandate_ref=ref), "now": T0})
    return out["data"]["encounter_id"]


def test_lock_b():
    state, ref = fresh_with_mandate(
        purpose_set=["DOCUMENTATION"],
        field_classes=["IDENTITY_CONTACT", "CLINICAL_CONTEXT_LIMITED"])
    enc = _started_encounter(state, ref)
    out = E.note_draft_create(state, {
        "encounter_ref": enc, "content": "Synthetic draft text.",
        "drafting_agent_id": "agent-doc"})
    draft = out["data"]["draft"]
    check("pin: draft carries UNSIGNED_DRAFT_NOT_RECORD standing",
          out["data"]["standing_status"]
          == "UNSIGNED_DRAFT_NOT_RECORD")
    did = draft["draft_id"]
    # H-7: draft ref through the record path -> zero draft bytes
    out = E.chart_record_read(state, {"ref": did})
    check("H-7: record read of draft -> UNSIGNED_DRAFT_NOT_RECORD",
          out["refusal_class"] == "UNSIGNED_DRAFT_NOT_RECORD")
    fp = E.note_fingerprint_get(state, {"draft_ref": did})
    check("pin: fingerprint stable + canonical (ws-equivalent)",
          fp["data"]["fingerprint"] == draft["fingerprint"])
    variant = {"content": "  Synthetic   draft text. \r\n",
               "author_agent_id": "agent-doc", "encounter_id": enc,
               "version": 1}
    check("pin: canon-v1 whitespace profile equivalence",
          E.note_fingerprint({**draft, "content":
                              "Synthetic draft text."})
          == draft["fingerprint"])
    # H-6: draft moves after sign request -> sign refuses
    fp_at_request = draft["fingerprint"]  # capture value, not ref
    req = E.note_sign_request(state, {
        "draft_ref": did, "fingerprint": fp_at_request,
        "treating_clinician_ref": "CLIN-CA-ONLY"})
    check("pin: sign request routes exact fingerprint",
          req["ok"] and req["data"]["routed_fingerprint"]
          == draft["fingerprint"])
    E.note_draft_create(state, {
        "encounter_ref": enc, "content": "Edited after request.",
        "drafting_agent_id": "agent-doc", "edit_of_draft_id": did})
    try:
        SIM.clinician_sign(state, did, fp_at_request,
                         "CLIN-CA-ONLY")
        check("H-6: moved draft sign refused", False)
    except E.Refusal as r:
        check("H-6: moved draft sign -> NOTE_FINGERPRINT_MISMATCH",
              r.refusal_class == "NOTE_FINGERPRINT_MISMATCH")
    status = E.note_signed_status_get(state, {"note_ref": did})
    check("H-6: draft remains UNSIGNED_DRAFT",
          status["data"]["status"] == "UNSIGNED_DRAFT")
    out = E.note_sign_request(state, {
        "draft_ref": did, "fingerprint": fp_at_request,
        "treating_clinician_ref": "CLIN-CA-ONLY"})
    check("pin: stale fingerprint at request refused",
          out["refusal_class"] == "NOTE_FINGERPRINT_MISMATCH")
    current = E.note_fingerprint_get(state, {"draft_ref": did})
    signed = SIM.clinician_sign(state, did,
                              current["data"]["fingerprint"],
                              "CLIN-CA-ONLY")
    note_id = signed["note_id"]
    status = E.note_signed_status_get(state, {"note_ref": note_id})
    check("pin: clinician sign lands exact fingerprint",
          status["data"]["status"] == "SIGNED" and
          status["data"]["note"]["signed_fingerprint"]
          == signed["signed_fingerprint"])
    # DT-2: edit attempt on signed draft -> ADDENDUM_REQUIRED
    out = E.note_draft_create(state, {
        "encounter_ref": enc, "content": "silent overwrite attempt",
        "drafting_agent_id": "agent-doc", "edit_of_draft_id": did})
    check("DT-2: post-signature edit -> ADDENDUM_REQUIRED",
          out["refusal_class"] == "ADDENDUM_REQUIRED")
    served = E.chart_record_read(state, {"ref": note_id})
    check("DT-2: chart still serves original signed bytes",
          served["data"]["note"]["content_snapshot"]
          == "Edited after request.")
    # addendum chain: new draft -> sign -> chain renders in order
    add = E.note_addendum_create(state, {
        "signed_note_ref": note_id,
        "content": "Addendum: synthetic correction.",
        "drafting_agent_id": "agent-doc"})
    check("pin: addendum cites original fingerprint",
          add["data"]["cites_fingerprint"]
          == signed["signed_fingerprint"])
    adid = add["data"]["draft"]["draft_id"]
    afp = E.note_fingerprint_get(state, {"draft_ref": adid})
    signed2 = SIM.clinician_sign(state, adid, afp["data"]["fingerprint"],
                               "CLIN-CA-ONLY")
    status = E.note_signed_status_get(state, {"note_ref": note_id})
    check("pin: addendum chain renders original -> addendum",
          [n["note_id"] for n in status["data"]["chain"]]
          == [note_id, signed2["note_id"]])
    # Pin Verifier tool: clean export passes, drifted export fails
    export = {"signed_notes": [signed, signed2],
              "served": {note_id: "Edited after request.",
                         signed2["note_id"]:
                         "Addendum: synthetic correction."}}
    out = note_pin_verifier.verify_pin(copy.deepcopy(export))
    check("Pin Verifier: intact chain verifies",
          out["ok"] and out["chain"] == [note_id,
                                         signed2["note_id"]])
    export["served"][note_id] = "tampered served bytes"
    out = note_pin_verifier.verify_pin(export)
    check("Pin Verifier: drift detected by name",
          not out["ok"] and out["findings"][0]["finding"]
          == "POST_SIGNATURE_DRIFT")
    # H-14: clinical content smuggled as a draft
    out = E.note_draft_create(state, {
        "encounter_ref": enc,
        "content": "Draft a note assessing whether we should "
                   "diagnose and prescribe",
        "drafting_agent_id": "agent-doc"})
    check("H-14: clinical draft -> CLINICAL_REQUEST + queued",
          out["refusal_class"] == "CLINICAL_REQUEST"
          and len(state["clinical_queue"]) == 1)


# ------------------------------------------------------------ Lock C
def test_lock_c():
    state, ref = fresh_with_mandate()  # SCHEDULING mandate
    # DT-3: scheduling mandate asks full chart
    out = E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-001", "purpose": "SCHEDULING",
        "mandate_ref": ref, "requested_classes": ["FULL_CHART"],
        "now": T0})
    check("DT-3: FULL_CHART refused FIELD_CLASS_NOT_GRANTED",
          out["refusal_class"] == "FIELD_CLASS_NOT_GRANTED")
    check("DT-3: refusal itself sealed in ledger",
          len(state["ledger"]) == 1 and
          state["ledger"][0]["verdict"]
          == "FIELD_CLASS_NOT_GRANTED" and
          out["access_record_ref"]
          == state["ledger"][0]["record_id"])
    # granted projection: only granted classes returned
    out = E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-001", "purpose": "SCHEDULING",
        "mandate_ref": ref,
        "requested_classes": ["IDENTITY_CONTACT", "APPOINTMENT"],
        "now": T0})
    ctx = out["data"]["context"]
    check("Lock C: projection returns only granted classes",
          out["ok"] and set(ctx) == {"IDENTITY_CONTACT",
                                     "APPOINTMENT"})
    check("Lock C: restricted classes never in projection",
          "PART2_SUD" not in ctx and "MINOR_RESTRICTED" not in ctx)
    # H-8: no purpose
    out = E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-001", "mandate_ref": ref, "now": T0})
    check("H-8: omitted purpose -> PURPOSE_NOT_DECLARED",
          out["refusal_class"] == "PURPOSE_NOT_DECLARED")
    out = E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-001", "purpose": "WHATEVER",
        "mandate_ref": ref, "now": T0})
    check("H-8: off-vocabulary purpose -> PURPOSE_NOT_DECLARED",
          out["refusal_class"] == "PURPOSE_NOT_DECLARED")
    # H-10: probing restricted class == same refusal shape
    out = E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-001", "purpose": "SCHEDULING",
        "mandate_ref": ref, "requested_classes": ["PART2_SUD"],
        "now": T0})
    check("H-10: Part 2 probe refused, identical shape",
          out["refusal_class"] == "FIELD_CLASS_NOT_GRANTED")
    check("H-10: probe sealed in ledger",
          state["ledger"][-1]["classes_requested"] == ["PART2_SUD"])
    # H-15: cross-tenant
    out = E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-002", "purpose": "SCHEDULING",
        "mandate_ref": ref, "requested_classes": ["IDENTITY_CONTACT"],
        "now": T0})
    check("H-15: cross-tenant read refused + sealed",
          out["refusal_class"] == "FIELD_CLASS_NOT_GRANTED"
          and state["ledger"][-1]["patient_ref"] == "PAT-SYN-002")
    # appointment read within classes
    out = E.appointment_get(state, {
        "appointment_ref": "APPT-SYN-001", "purpose": "SCHEDULING",
        "mandate_ref": ref, "now": T0})
    check("Lock C: appointment within granted classes ok",
          out["ok"] and "when" in
          out["data"]["appointment"]["APPOINTMENT"]["when"]
          or out["ok"])
    # access pack: audit purpose + chain verify + tamper (H-16)
    out = E.access_pack_get(state, {
        "practice_id": "PRAC-SYN-1", "mandate_ref": ref,
        "purpose": "AUDIT_REVIEW", "now": T0})
    check("ledger: AUDIT_REVIEW outside SCHEDULING-only mandate "
          "-> PURPOSE_NOT_GRANTED (mandate purpose_set enforced)",
          out["refusal_class"] == "PURPOSE_NOT_GRANTED")
    audit_state, audit_ref = fresh_with_mandate(
        purpose_set=["SCHEDULING", "AUDIT_REVIEW"])
    E.patient_context_get(audit_state, {
        "patient_ref": "PAT-SYN-001", "purpose": "SCHEDULING",
        "mandate_ref": audit_ref,
        "requested_classes": ["IDENTITY_CONTACT"], "now": T0})
    pack = E.access_pack_get(audit_state, {
        "practice_id": "PRAC-SYN-1", "mandate_ref": audit_ref,
        "purpose": "AUDIT_REVIEW", "now": T0})
    check("ledger: pack exports records + FHIR AuditEvent map",
          pack["ok"] and pack["data"]["fhir_audit_events"][0][
              "resourceType"] == "AuditEvent")
    ver = E.access_pack_verify(audit_state, {
        "access_pack": {"records": pack["data"]["records"]}})
    check("ledger: offline verify passes on intact chain",
          ver["ok"] and ver["data"]["chain_ok"])
    tampered = copy.deepcopy(pack["data"]["records"])
    tampered[0]["classes_returned"] = ["FULL_CHART"]
    ver = E.access_pack_verify(audit_state, {
        "access_pack": {"records": tampered}})
    check("H-16: tampered copy fails verify loudly",
          not ver["ok"] or not ver["data"]["chain_ok"])
    out = access_ledger_verifier.verify_pack(
        {"records": tampered})
    check("H-16: Ledger Verifier tool cites failing record",
          not out["ok"] and out["findings"][0]["finding"]
          == "CHAIN_BREAK")
    out = access_ledger_verifier.verify_pack(
        {"records": pack["data"]["records"]},
        {"from": T0, "to": T0})
    check("ledger: covered interval passes completeness",
          out["ok"])


# ------------------------------------------------------------ intake
def test_intake():
    state, ref = fresh_with_mandate(
        purpose_set=["INTAKE_ADMIN"],
        field_classes=["IDENTITY_CONTACT"])
    out = E.intake_template_get(state, {
        "practice_id": "PRAC-SYN-1", "visit_type": "VIDEO_FOLLOWUP"})
    check("intake: template served (administrative only)",
          out["ok"])
    out = E.intake_template_get(state, {
        "practice_id": "PRAC-SYN-1", "visit_type": "VIDEO_INITIAL"})
    check("intake: missing template -> TEMPLATE_NOT_FOUND",
          out["refusal_class"] == "TEMPLATE_NOT_FOUND")
    out = E.intake_status_get(state, {
        "intake_ref": "INT-SYN-001", "purpose": "INTAKE_ADMIN",
        "mandate_ref": ref, "now": T0})
    check("intake: status source-labeled + sealed",
          out["ok"] and out["data"]["sections"][0]["source"]
          == "patient" and out["access_record_ref"] is not None)


# ------------------------------------------------------------ Bridge
def test_bridge_baa():
    state = E.fresh_state()
    out = E.bridge_sandbox_read(state, {})
    check("bridge: sandbox read ok, synthetic only",
          out["ok"] and out["data"]["mode"] == "sandbox")
    # self-check (c): no BAA artifact -> BAA_REQUIRED
    out = E.bridge_live_read(state, {"deployment_id": "DEP-1"})
    check("self-check(c)/H-13: live read, no BAA -> BAA_REQUIRED",
          out["refusal_class"] == "BAA_REQUIRED")
    E.bridge_configure(state, {
        "deployment_id": "DEP-2", "baa_artifact_ref": "BAA-REF-1",
        "path_components": ["hosting", "logging"],
        "flow_down_inventory": ["hosting"]})
    out = E.bridge_live_read(state, {"deployment_id": "DEP-2"})
    check("H-13: missing flow-down -> BAA_REQUIRED",
          out["refusal_class"] == "BAA_REQUIRED")
    E.bridge_configure(state, {
        "deployment_id": "DEP-3", "baa_artifact_ref": "BAA-REF-1",
        "path_components": ["hosting"],
        "flow_down_inventory": ["hosting"]})
    out = E.bridge_live_read(state, {"deployment_id": "DEP-3"})
    check("bridge: gate passes w/ full chain but P0 has no live "
          "adapter (still BAA_REQUIRED-shaped, zero bytes)",
          out["refusal_class"] == "BAA_REQUIRED")


# ------------------------------------------------- standalone tools
def test_standalone_tools():
    pack = E.pack_for("SYN-CA")
    facts = [{"state": "SYN-CA", "status": "ACTIVE",
              "source": "SYNTHETIC-ROSTER-FEED-v1", "as_of": T0}]
    out = encounter_gate.gate_check(facts, pack, "SYN-CA",
                                    "VIDEO_FOLLOWUP",
                                    ["telehealth"], now=T0)
    check("Gate tool: standalone pass verdict", out["ok"])
    out = encounter_gate.gate_check(facts, pack, "SYN-NY",
                                    "VIDEO_FOLLOWUP",
                                    ["telehealth"], now=T0)
    check("Gate tool: no fact for state -> fail closed",
          out["refusal_class"] == "LICENSE_STATE_UNVERIFIED")
    out = policy_pack_workbench.transition(
        {"state": "COUNSEL_REVIEW", "version": "0.2.0",
         "counsel_signoff_ref": None}, "SIGNED")
    check("Workbench: SIGNED blocked without counsel ref",
          not out["ok"])
    out = policy_pack_workbench.transition(
        {"state": "COUNSEL_REVIEW", "version": "0.2.0",
         "counsel_signoff_ref": None}, "SIGNED",
        counsel_signoff_ref="COUNSEL-REF-X")
    check("Workbench: SIGNED with counsel ref ok",
          out["ok"] and out["pack"]["state"] == "SIGNED")
    check("Workbench: servable() false for DRAFT pack",
          policy_pack_workbench.servable(E.pack_for("SYN-WA"),
                                         now=T0) is False)
    check("Workbench: servable() true for IN_FORCE pack",
          policy_pack_workbench.servable(pack, now=T0) is True)


# ------------------------------------------------- self-check (e)
def test_no_network():
    src = ""
    for path in [HERE / "meridian_engine.py", HERE / "server.py",
                 *sorted((HERE / "tools").glob("*.py"))]:
        src += path.read_text()
    bad = re.findall(r"import (requests|urllib|socket|httpx)|"
                     r"urlopen|http\.client", src)
    check("self-check(e): no live-network code paths", bad == [],
          str(bad))


def main():
    for fn in (test_surface_no_finalize, test_guards, test_mandates,
               test_lock_a, test_lock_b, test_lock_c, test_intake,
               test_bridge_baa, test_standalone_tools,
               test_no_network):
        fn()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", *FAIL, sep="\n  ")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())

# Eclipse Meridian MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
