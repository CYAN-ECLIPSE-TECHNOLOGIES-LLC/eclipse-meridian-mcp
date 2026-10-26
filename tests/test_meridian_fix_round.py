# Eclipse Meridian MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Fix-round regressions: B-MER-1..5 + FULL_CHART adjudication, bench shapes replicated.

"""Fix-round regression suite (Verity bench 2026-10-26 FAILED).

Every regression replicates the bench's own shapes BYTE-FOR-BYTE
from the retained scorecard evidence: her import probe
(`import meridian_engine; clinician_sign(state,draft,fp,signer)`),
her fuzz shapes (string/int consent_artifacts, dict/list class
elements, int record elements, 1500-deep nested arg), and her
two-tenant setup. No diverged friendlier shapes.
"""
import copy
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "tests"))
import meridian_engine as E  # noqa: E402

T0 = "2026-10-25T10:00:00Z"
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


def upsert(state, payload):
    signed = E.sign_mandate_payload(copy.deepcopy(payload))
    return E.mandate_upsert(state, {"channel": "customer_admin",
                                    "payload": signed, "now": T0})


def draft_enc(mandate_ref, consents=("telehealth",)):
    artifacts = [{"consent_type": c, "participant_ref": "PAT-SYN-001",
                  "method": "verbal", "captured_at": T0}
                 for c in consents]
    return {"clinician_id": "CLIN-CA-ONLY",
            "patient_ref": "PAT-SYN-001", "patient_state": "SYN-CA",
            "visit_type": "VIDEO_FOLLOWUP", "profession_class": "MD",
            "mandate_ref": mandate_ref, "practice_id": "PRAC-SYN-1",
            "consent_artifacts": artifacts, "participants": [],
            "recording_requested": False}


def fresh_with_mandate(**over):
    state = E.fresh_state()
    out = upsert(state, mandate_payload(**over))
    assert out["ok"], out
    return state, out["data"]["mandate_ref"]


# ------------------------------------------------------- B-MER-1
def test_b_mer_1_no_signing_capability():
    # Bench probe, byte-for-byte: import the shipped engine and
    # call clinician_sign(state, draft, fp, signer) on a live draft.
    state, ref = fresh_with_mandate(
        purpose_set=["DOCUMENTATION"],
        field_classes=["IDENTITY_CONTACT",
                       "CLINICAL_CONTEXT_LIMITED"])
    out = E.encounter_schedule(state, {
        "encounter_draft": draft_enc(ref), "now": T0})
    enc = out["data"]["encounter_id"]
    draft = E.note_draft_create(state, {
        "encounter_ref": enc, "content": "Synthetic draft text.",
        "drafting_agent_id": "agent-doc"})["data"]["draft"]
    fp = draft["fingerprint"]
    probe = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); "
         "import meridian_engine; "
         "meridian_engine.clinician_sign(state, draft, fp, signer)",
         str(HERE)],
        capture_output=True, text=True)
    check("B-MER-1: bench import probe cannot reach a sign "
          "function (AttributeError/NameError, non-zero exit)",
          probe.returncode != 0 and
          ("clinician_sign" in probe.stderr), probe.stderr[-200:])
    check("B-MER-1: shipped engine has no clinician_sign attr",
          not hasattr(E, "clinician_sign"))
    status = E.note_signed_status_get(state,
                                      {"note_ref": draft["draft_id"]})
    check("B-MER-1: draft remains UNSIGNED_DRAFT after probe",
          status["data"]["status"] == "UNSIGNED_DRAFT")
    check("B-MER-1: no signed notes exist in state",
          state["signed_notes"] == {})
    # Reachability sweep over the SHIPPED tree (product files
    # only; tests/ is the fixture home and is excluded by design).
    shipped = [HERE / "meridian_engine.py", HERE / "server.py",
               *sorted((HERE / "tools").glob("*.py"))]
    src = "\n".join(p.read_text() for p in shipped)
    check("B-MER-1 sweep: no 'clinician_sign' in any shipped file",
          "clinician_sign" not in src)
    check("B-MER-1 sweep: no signed-note creation in shipped code",
          not re.search(r'signed_notes"\]\[[^\]]+\]\s*=', src) and
          '"signed": True' not in src and
          'draft["signed"] = True' not in src)
    check("B-MER-1 sweep: no shipped module imports the fixture",
          "clinician_sign_simulator" not in src)


# ------------------------------------------------------- B-MER-2
def test_b_mer_2_access_pack_purpose():
    state, sched_ref = fresh_with_mandate()  # SCHEDULING only
    out = E.access_pack_get(state, {
        "practice_id": "PRAC-SYN-1", "mandate_ref": sched_ref,
        "purpose": "AUDIT_REVIEW", "now": T0})
    check("B-MER-2: SCHEDULING-only mandate + AUDIT_REVIEW -> "
          "PURPOSE_NOT_GRANTED (membership enforced, no pack)",
          not out["ok"] and
          out["refusal_class"] == "PURPOSE_NOT_GRANTED")
    out = E.access_pack_get(state, {
        "practice_id": "PRAC-SYN-1", "mandate_ref": sched_ref,
        "purpose": "SCHEDULING", "now": T0})
    check("B-MER-2: declared-but-wrong purpose -> "
          "PURPOSE_NOT_GRANTED (not PURPOSE_NOT_DECLARED)",
          out["refusal_class"] == "PURPOSE_NOT_GRANTED")
    out = E.access_pack_get(state, {
        "practice_id": "PRAC-SYN-1", "mandate_ref": sched_ref,
        "now": T0})
    check("B-MER-2: undeclared purpose -> PURPOSE_NOT_DECLARED",
          out["refusal_class"] == "PURPOSE_NOT_DECLARED")
    audit_ref = upsert(state, mandate_payload(
        purpose_set=["SCHEDULING", "AUDIT_REVIEW"]))[
        "data"]["mandate_ref"]
    out = E.access_pack_get(state, {
        "practice_id": "PRAC-SYN-1", "mandate_ref": audit_ref,
        "purpose": "AUDIT_REVIEW", "now": T0})
    check("B-MER-2: AUDIT_REVIEW in mandate purpose_set exports",
          out["ok"])


# ------------------------------------------------------- B-MER-3
def test_b_mer_3_tenant_isolation():
    state = E.fresh_state()
    ref1 = upsert(state, mandate_payload(
        purpose_set=["SCHEDULING", "AUDIT_REVIEW"]))[
        "data"]["mandate_ref"]
    ref2 = upsert(state, mandate_payload(
        agent_id="agent-tenant2", practice_id="PRAC-SYN-2",
        purpose_set=["SCHEDULING", "AUDIT_REVIEW"]))[
        "data"]["mandate_ref"]
    E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-001", "purpose": "SCHEDULING",
        "mandate_ref": ref1, "requested_classes":
        ["IDENTITY_CONTACT"], "now": T0})
    E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-002", "purpose": "SCHEDULING",
        "mandate_ref": ref2, "requested_classes":
        ["IDENTITY_CONTACT"], "now": T0})
    # Cross-tenant attempt (bench H-15/G1 shape).
    out = E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-002", "purpose": "SCHEDULING",
        "mandate_ref": ref1, "requested_classes":
        ["IDENTITY_CONTACT"], "now": T0})
    check("B-MER-3: cross-tenant read refused",
          out["refusal_class"] == "FIELD_CLASS_NOT_GRANTED")
    pack1 = E.access_pack_get(state, {
        "practice_id": "PRAC-SYN-1", "mandate_ref": ref1,
        "purpose": "AUDIT_REVIEW", "now": T0})["data"]["records"]
    pack2 = E.access_pack_get(state, {
        "practice_id": "PRAC-SYN-2", "mandate_ref": ref2,
        "purpose": "AUDIT_REVIEW", "now": T0})["data"]["records"]
    check("B-MER-3: tenant-1 pack contains ONLY PRAC-SYN-1 "
          "records", pack1 and all(
              r["practice_id"] == "PRAC-SYN-1" for r in pack1),
          str([r["practice_id"] for r in pack1]))
    check("B-MER-3: tenant-2 pack contains ONLY PRAC-SYN-2 "
          "records", pack2 and all(
              r["practice_id"] == "PRAC-SYN-2" for r in pack2),
          str([r["practice_id"] for r in pack2]))
    check("B-MER-3: tenant-1 patient records absent from "
          "tenant-2 pack (no PAT-SYN-001 leak)",
          all(r["patient_ref"] != "PAT-SYN-001" for r in pack2))
    check("B-MER-3: tenant-2 own read present in tenant-2 pack",
          any(r["patient_ref"] == "PAT-SYN-002" and
              r["verdict"] == "GRANTED" for r in pack2))
    check("B-MER-3/H-15: cross-tenant refusal sealed in BOTH "
          "tenants' audit views",
          any(r["patient_ref"] == "PAT-SYN-002" and
              r["verdict"] == "FIELD_CLASS_NOT_GRANTED"
              for r in pack1) and
          any(r["patient_ref"] == "PAT-SYN-002" and
              r["verdict"] == "FIELD_CLASS_NOT_GRANTED"
              for r in pack2))
    for label, pack in (("tenant-1", pack1), ("tenant-2", pack2)):
        ver = E.access_pack_verify(state, {
            "access_pack": {"records": pack}})
        check(f"B-MER-3: {label} pack chain verifies standalone",
              ver["ok"] and ver["data"]["chain_ok"])


# ------------------------------------------------------- B-MER-4
def test_b_mer_4_gate_refusals_seal():
    state, ref = fresh_with_mandate()
    E.patient_context_get(state, {
        "patient_ref": "PAT-SYN-001", "purpose": "SCHEDULING",
        "mandate_ref": ref, "requested_classes":
        ["IDENTITY_CONTACT"], "now": T0})
    before = len(state["ledger"])
    out = E.encounter_gate_check(state, {
        "encounter_draft": draft_enc(ref, consents=()), "now": T0})
    check("B-MER-4: refused gate_check seals a ledger record",
          out["refusal_class"] == "CONSENT_SET_INCOMPLETE" and
          len(state["ledger"]) == before + 1)
    rec = state["ledger"][-1]
    check("B-MER-4: gate refusal record is 164.312(b)-shaped",
          all(k in rec for k in (
              "record_id", "agent_id", "patient_ref",
              "classes_requested", "classes_returned", "purpose",
              "ts", "mandate_ref", "verdict", "prev_hash", "hash",
              "practice_id")) and
          rec["patient_ref"] == "PAT-SYN-001" and
          rec["verdict"] == "CONSENT_SET_INCOMPLETE" and
          rec["practice_id"] == "PRAC-SYN-1")
    check("B-MER-4: verdict carries the sealed record ref",
          out["access_record_ref"] == rec["record_id"])
    out = E.encounter_schedule(state, {
        "encounter_draft": {**draft_enc(ref),
                            "patient_state": "SYN-NY"}, "now": T0})
    check("B-MER-4: refused schedule seals a ledger record",
          out["refusal_class"] == "JURISDICTION_MISMATCH" and
          len(state["ledger"]) == before + 2 and
          state["ledger"][-1]["verdict"]
          == "JURISDICTION_MISMATCH" and
          out["access_record_ref"]
          == state["ledger"][-1]["record_id"])
    check("B-MER-4: refused schedule still books nothing",
          state["encounters"] == {})


# --------------------------------------------------------- OBS
def test_obs_full_chart_not_grantable():
    state = E.fresh_state()
    out = upsert(state, mandate_payload(
        purpose_set=["DOCUMENTATION"],
        field_classes=["IDENTITY_CONTACT", "FULL_CHART"]))
    check("OBS: FULL_CHART on DOCUMENTATION -> "
          "MANDATE_TERM_NOT_GRANTABLE (restrictive 6.3 reading)",
          out["refusal_class"] == "MANDATE_TERM_NOT_GRANTABLE")


# ------------------------------------------------------- B-MER-5
def _server_session():
    tmp = tempfile.NamedTemporaryFile(
        suffix="-meridian-state.json", delete=False)
    tmp.close()
    env = dict(os.environ, ECLIPSE_MERIDIAN_STATE=tmp.name)
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "server.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        text=True, env=env, cwd=str(HERE))
    counter = [0]

    def call(name, arguments, raw_line=None):
        counter[0] += 1
        rid = counter[0]
        if raw_line is None:
            line = json.dumps({"jsonrpc": "2.0", "id": rid,
                               "method": "tools/call",
                               "params": {"name": name,
                                          "arguments": arguments}})
        else:
            line = raw_line(rid)
        proc.stdin.write(line + "\n")
        proc.stdin.flush()
        return rid, json.loads(proc.stdout.readline())

    return proc, call


def _named(resp):
    """A response is a NAMED refusal (never raw -32603) when it
    carries a result envelope or a -32602, and its text names a
    refusal/error class."""
    if "error" in resp:
        return resp["error"].get("code") == -32602
    text = resp["result"]["content"][0]["text"]
    return bool(re.search(r"[A-Z][A-Z_]{3,}", text))


def test_b_mer_5_fuzz_no_32603():
    proc, call = _server_session()
    try:
        payload = E.sign_mandate_payload(mandate_payload())
        _, resp = call("mandate_upsert", {
            "channel": "customer_admin", "payload": payload,
            "now": T0})
        ref = json.loads(resp["result"]["content"][0]["text"])[
            "data"]["mandate_ref"]
        _, resp = call("encounter_schedule", {
            "encounter_draft": draft_enc(ref), "now": T0})
        enc = json.loads(resp["result"]["content"][0]["text"])[
            "data"]["encounter_id"]
        probes = []
        # Bench shape: encounter_start_gate / str consent artifact
        probes.append(("start_gate/str-consent-artifact",
                       *call("encounter_start_gate", {
                           "encounter_ref": enc,
                           "patient_state": "SYN-CA",
                           "consent_artifacts": ["str-artifact"],
                           "now": T0})))
        # Bench shape: encounter_gate_check / int consent artifact
        bad_draft = draft_enc(ref)
        bad_draft["consent_artifacts"] = [42]
        probes.append(("gate_check/int-consent-artifact",
                       *call("encounter_gate_check", {
                           "encounter_draft": bad_draft,
                           "now": T0})))
        # Bench shapes: patient_context_get dict/list class elems
        probes.append(("context/dict-class-elem",
                       *call("patient_context_get", {
                           "patient_ref": "PAT-SYN-001",
                           "purpose": "SCHEDULING",
                           "mandate_ref": ref,
                           "requested_classes": [{"x": 1}],
                           "now": T0})))
        probes.append(("context/list-class-elem",
                       *call("patient_context_get", {
                           "patient_ref": "PAT-SYN-001",
                           "purpose": "SCHEDULING",
                           "mandate_ref": ref,
                           "requested_classes": [["x"]],
                           "now": T0})))
        # Bench shape: access_pack_verify / int record elements
        probes.append(("verify/int-record-elems",
                       *call("access_pack_verify", {
                           "access_pack": {"records": [1, 2, 3]}})))
        # Bench shape H2: 1500-deep nested key in tool args,
        # request line built by concatenation (no recursion).
        def deep_line(rid):
            return ('{"jsonrpc":"2.0","id":%d,"method":"tools/call",'
                    '"params":{"name":"mandate_get","arguments":'
                    '{"mandate_ref":"%s","now":"%s","probe":'
                    % (rid, ref, T0)
                    + '{"a":' * 1500 + "1" + "}" * 1500 + "}}}")
        probes.append(("deep-nesting-1500",
                       *call("mandate_get", {}, raw_line=deep_line)))
        for label, rid, resp in probes:
            check(f"B-MER-5 {label}: no raw -32603",
                  resp.get("error", {}).get("code") != -32603,
                  str(resp)[:200])
            check(f"B-MER-5 {label}: response id preserved",
                  resp.get("id") == rid, str(resp)[:120])
            check(f"B-MER-5 {label}: named refusal/verdict",
                  _named(resp), str(resp)[:200])
        proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": 999, "method": "ping"}) + "\n")
        proc.stdin.flush()
        alive = json.loads(proc.stdout.readline())
        check("B-MER-5: server alive after fuzz, answers ping "
              "with its id", alive.get("id") == 999 and
              alive.get("result") == {})
    finally:
        proc.terminate()
    # Engine-level: the deep scan itself is iterative + bounded.
    deep = current = {}
    for _ in range(1500):
        current["a"] = {}
        current = current["a"]
    try:
        E.deep_key_scan(deep)
        check("B-MER-5: deep_key_scan 1500-deep refuses by name",
              False)
    except E.ToolError as exc:
        check("B-MER-5: deep_key_scan 1500-deep refuses by name",
              "NESTING_TOO_DEEP" in str(exc))
    except RecursionError:
        check("B-MER-5: deep_key_scan 1500-deep refuses by name",
              False, "RecursionError escaped")


def main():
    for fn in (test_b_mer_1_no_signing_capability,
               test_b_mer_2_access_pack_purpose,
               test_b_mer_3_tenant_isolation,
               test_b_mer_4_gate_refusals_seal,
               test_obs_full_chart_not_grantable,
               test_b_mer_5_fuzz_no_32603):
        fn()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", *FAIL, sep="\n  ")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())

# Eclipse Meridian MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
