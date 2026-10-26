#!/usr/bin/env python3
# Eclipse Meridian MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Meridian Core engine: three locks (jurisdiction gate, note pin, minimum-necessary reads) over synthetic data only.

"""Eclipse Meridian — governed telehealth operations —
jurisdiction-gated encounters, signed-note integrity, PHI access
evidence. Not a healthcare provider.

P0: synthetic-only (HAPI FHIR sandbox stand-in + Synthea-shaped
fixtures). No live PHI, no real EHR connection, NO prescribing
surface in any phase, and NO agent tool that finalizes/signs a
note into the record (spec section 6.2 product law): drafts stay
cryptographically OUTSIDE the record until the treating clinician
signs the exact fingerprint (UNSIGNED_DRAFT_NOT_RECORD).
"""
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
DATA = HERE / "data"
KEY_PATH = HERE / "keys" / "admin-key.local.json"
STATE_PATH = Path(__import__("os").environ.get(
    "ECLIPSE_MERIDIAN_STATE", str(DATA / "state.json")))

VERSION = "0.1.0"
DESCRIPTOR = ("Eclipse Meridian — governed telehealth operations — "
              "jurisdiction-gated encounters, signed-note integrity, "
              "PHI access evidence. Not a healthcare provider.")
PRODUCT = "Eclipse Meridian"

PURPOSES = ("SCHEDULING", "INTAKE_ADMIN", "ENCOUNTER_SUPPORT",
            "DOCUMENTATION", "AUDIT_REVIEW")
FIELD_CLASSES = ("IDENTITY_CONTACT", "APPOINTMENT", "INSURANCE_ADMIN",
                 "CLINICAL_CONTEXT_LIMITED", "FULL_CHART")
RESTRICTED_CLASSES = ("PART2_SUD", "MINOR_RESTRICTED")
CLINICAL_CONTEXT_PURPOSES = ("ENCOUNTER_SUPPORT", "DOCUMENTATION")

REFUSALS = (
    "JURISDICTION_MISMATCH", "LICENSE_STATE_UNVERIFIED",
    "CONSENT_SET_INCOMPLETE", "RECORDING_CONSENT_MISSING",
    "VISIT_TYPE_OUTSIDE_MANDATE", "MANDATE_NOT_FOUND",
    "MANDATE_EXPIRED", "MANDATE_SIGNATURE_INVALID",
    "MANDATE_TERM_NOT_GRANTABLE", "POLICY_PACK_UNSIGNED",
    "POLICY_PACK_STALE", "JURISDICTION_NOT_IN_PACK",
    "UNSIGNED_DRAFT_NOT_RECORD", "NOTE_FINGERPRINT_MISMATCH",
    "ADDENDUM_REQUIRED", "DRAFT_NOT_FOUND",
    "FIELD_CLASS_NOT_GRANTED", "PURPOSE_NOT_DECLARED",
    "PURPOSE_NOT_GRANTED",
    "CLINICAL_REQUEST", "DEVICE_CDS_BOUNDARY",
    "BAA_REQUIRED", "ENCOUNTER_NOT_FOUND", "TEMPLATE_NOT_FOUND",
)

# Clinical-content tripwires (routing only — never an answer):
# a request matching one returns CLINICAL_REQUEST and is queued
# intact for the treating clinician (spec section 6.5).
CLINICAL_PATTERNS = (
    "diagnos", "prescrib", "should we treat", "treat with",
    "assess whether", "risk score", "triage", "dosage", "dose of",
    "eligible for care", "coverage determination",
)

# Deep-key denylist: keys that may never arrive inside tool input
# at any nesting depth (finalize/sign/override-shaped smuggling).
DENY_KEYS = ("finalize", "finalise", "sign_note", "signoff",
             "sign_off", "override", "bypass", "force_sign",
             "auto_sign", "prescription", "prescribe")


class ToolError(Exception):
    """Malformed input refused BY NAME at the boundary."""


class Refusal(Exception):
    """Named refusal class (spec section 6.4 registry)."""

    def __init__(self, refusal_class, detail, cited_fact=None):
        super().__init__(f"{refusal_class}: {detail}")
        self.refusal_class = refusal_class
        self.detail = detail
        self.cited_fact = cited_fact


# ------------------------------------------------------------ guards
_INT_SHAPED_RE = re.compile(r"^[+-]?\d+$")
_OFFSET_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def coerce_int_param(value, name, refusal="INT_PARAM_INVALID"):
    """House reference guard: accept a real int, an int-shaped
    string, or an integral float; refuse bools, non-numeric strings,
    non-integral floats and containers BY NAME."""
    if isinstance(value, bool):
        raise ToolError(f"{refusal}: {name} must be an integer, "
                        f"not a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _INT_SHAPED_RE.match(value.strip()):
        return int(value.strip())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise ToolError(f"{refusal}: {name} must be an integer (got "
                    f"{type(value).__name__}); refused by name")


def parse_time(value, field="time"):
    """Parse ISO-8601 ONLY with an explicit offset; offset-less
    timestamps are refused by name — never guessed."""
    if not isinstance(value, str) or not value.strip():
        raise ToolError(f"PARSE_TIME_INVALID: {field} must be an "
                        f"ISO-8601 timestamp string with an offset")
    text = value.strip()
    if not _OFFSET_RE.search(text):
        raise ToolError(f"PARSE_TIME_NO_OFFSET: {field}={text!r} "
                        f"has no UTC offset; never guessed")
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ToolError(f"PARSE_TIME_INVALID: {field}={text!r}")
    if dt.tzinfo is None:
        raise ToolError(f"PARSE_TIME_NO_OFFSET: {field}={text!r}")
    return dt.astimezone(timezone.utc)


def require_ref_param(value, name):
    """Reference-type guard: every ref crossing the boundary is a
    non-empty string; dict/list/int refs are refused BY NAME —
    never stringified into a lookup."""
    if not isinstance(value, str) or not value.strip():
        raise ToolError(
            f"REF_TYPE_INVALID: {name} must be a non-empty string "
            f"reference (got {type(value).__name__}); refused by "
            f"name, never coerced")
    return value.strip()


def require_container_param(value, name, expected):
    """House boundary guard: structured params arrive as the
    container their schema declares, or refuse BY NAME."""
    ok = isinstance(value, dict) if expected == "object" \
        else isinstance(value, list)
    if not ok:
        raise ToolError(
            f"CONTAINER_TYPE_INVALID: {name} must be an {expected} "
            f"(got {type(value).__name__}); refused by name")
    return value


MAX_ARG_DEPTH = 64


def deep_key_scan(value, path="args"):
    """Deep-key scan: walk every nesting level of tool input and
    refuse any denylisted key BY NAME (finalize/sign/override/
    prescribe-shaped smuggling), however deeply buried. ITERATIVE
    (explicit stack, never recursion) with a bounded nesting
    depth: input nested past MAX_ARG_DEPTH is refused BY NAME
    (NESTING_TOO_DEEP) instead of escaping as a RecursionError
    that loses the JSON-RPC response id."""
    stack = [(value, path, 0)]
    while stack:
        current, current_path, depth = stack.pop()
        if depth > MAX_ARG_DEPTH:
            raise ToolError(
                f"NESTING_TOO_DEEP: {current_path} exceeds the "
                f"maximum argument nesting depth of "
                f"{MAX_ARG_DEPTH}; refused by name")
        if isinstance(current, dict):
            for key, sub in current.items():
                lowered = str(key).lower()
                for deny in DENY_KEYS:
                    if deny in lowered:
                        raise ToolError(
                            f"DENIED_KEY: {current_path}.{key} "
                            f"matches denylist entry {deny!r}; no "
                            f"finalize/sign/override/prescribing "
                            f"surface exists in Meridian")
                stack.append((sub, f"{current_path}.{key}",
                              depth + 1))
        elif isinstance(current, list):
            for i, sub in enumerate(current):
                stack.append((sub, f"{current_path}[{i}]",
                              depth + 1))
    return value


def require_string_elements(value, name):
    """Element-type guard: every element of a list-typed tool
    parameter must be a string; a dict/list/int element is
    refused BY NAME — never hashed, subscripted, or coerced
    (an unhashable element must not escape as a TypeError)."""
    for i, element in enumerate(value):
        if not isinstance(element, str):
            raise ToolError(
                f"ELEMENT_TYPE_INVALID: {name}[{i}] must be a "
                f"string (got {type(element).__name__}); refused "
                f"by name, never coerced")
    return value


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0).isoformat()


def _now(now=None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, str):
        return parse_time(now, "now")
    return now


def _tid(prefix):
    return f"{prefix}-{secrets.token_hex(4).upper()}"


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ------------------------------------------------------------- state
def fresh_state() -> dict:
    return {"mandates": {}, "encounters": {}, "packs": {},
            "drafts": {}, "signed_notes": {}, "sign_requests": {},
            "ledger": [], "admin_log": [], "clinical_queue": [],
            "deployments": {}, "seq": 0}


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            state = json.loads(STATE_PATH.read_text())
            for key, val in fresh_state().items():
                state.setdefault(key, val)
            return state
        except (ValueError, OSError):
            pass
    return fresh_state()


def save_state(state) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=1))


def _fixtures(name):
    return json.loads((DATA / name).read_text())


# -------------------------------------------------- verdict (10.5)
def verdict(ok, data=None, refusal_class=None, detail="",
            cited_fact=None, mandate_ref=None, pack_version=None,
            ts=None, access_record_ref=None):
    return {"ok": ok, "refusal_class": refusal_class,
            "detail": detail, "cited_fact": cited_fact,
            "mandate_ref": mandate_ref,
            "policy_pack_version": pack_version,
            "ts": ts or now_iso(),
            "access_record_ref": access_record_ref,
            "descriptor": DESCRIPTOR, "data": data or {}}


def refuse(state, cls, detail, cited_fact=None, mandate_ref=None,
           pack_version=None, ts=None):
    return verdict(False, refusal_class=cls, detail=detail,
                   cited_fact=cited_fact, mandate_ref=mandate_ref,
                   pack_version=pack_version, ts=ts)


# ---------------------------------------------------- admin signing
def ensure_admin_key() -> str:
    if KEY_PATH.exists():
        return json.loads(KEY_PATH.read_text())["key"]
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    KEY_PATH.write_text(json.dumps(
        {"key": key, "note": "Herald-pattern practice-admin signing "
                             "key (local fixture). Customer-admin "
                             "channel only; never an agent input."}))
    return key


def mandate_signature(payload: dict) -> str:
    body = {k: payload[k] for k in sorted(payload)
            if k != "signature"}
    return hmac.new(ensure_admin_key().encode(),
                    canonical_json(body).encode(),
                    hashlib.sha256).hexdigest()


def sign_mandate_payload(payload: dict) -> dict:
    """Customer-admin helper (Workbench/admin channel + tests):
    returns the payload with its Herald-pattern signature."""
    out = dict(payload)
    out["signature"] = mandate_signature(out)
    return out


# --------------------------------------------------------- mandates
def _mandate_live(state, mandate_ref, now):
    mandate = state["mandates"].get(mandate_ref)
    if mandate is None:
        raise Refusal("MANDATE_NOT_FOUND",
                      f"no mandate {mandate_ref}")
    if parse_time(mandate["expiry"], "expiry") <= now:
        raise Refusal("MANDATE_EXPIRED",
                      f"mandate {mandate_ref} expired at "
                      f"{mandate['expiry']}")
    return mandate


def mandate_upsert(state, args):
    """Customer-admin channel ONLY (verified-approval pattern for
    T3-class verbs): a Herald-signed payload arriving on the admin
    channel. Agent-session calls refuse — agents cannot amend
    mandates, including on the practice owner's in-session word
    (Steward T3, spec sections 6.1 / 13.2 H-4)."""
    now = _now(args.get("now"))
    channel = args.get("channel")
    payload = require_container_param(
        args.get("payload"), "payload", "object")
    if channel != "customer_admin":
        state["admin_log"].append(
            {"event": "MANDATE_UPSERT_ATTEMPT_AGENT_CHANNEL",
             "ts": now_iso(), "actor": args.get("actor", "agent")})
        return refuse(state, "MANDATE_SIGNATURE_INVALID",
                      "mandate_upsert is callable only from the "
                      "customer-admin channel with a Herald "
                      "signature; agent sessions cannot amend "
                      "mandates (Steward T3)")
    expected = mandate_signature(payload)
    if not hmac.compare_digest(str(payload.get("signature", "")),
                               expected):
        return refuse(state, "MANDATE_SIGNATURE_INVALID",
                      "Herald signature does not verify")
    for field in ("agent_id", "practice_id", "purpose_set",
                  "field_classes", "visit_types", "expiry"):
        if field not in payload:
            raise ToolError(f"MANDATE_FIELD_MISSING: {field}")
    purposes = require_container_param(
        payload["purpose_set"], "purpose_set", "array")
    classes = require_container_param(
        payload["field_classes"], "field_classes", "array")
    require_string_elements(purposes, "purpose_set")
    require_string_elements(classes, "field_classes")
    require_string_elements(
        require_container_param(payload.get("visit_types", []),
                                "visit_types", "array"),
        "visit_types")
    for purpose in purposes:
        if purpose not in PURPOSES:
            return refuse(state, "MANDATE_TERM_NOT_GRANTABLE",
                          f"purpose {purpose!r} is outside the "
                          f"closed vocabulary")
    for cls in classes:
        if cls in RESTRICTED_CLASSES:
            return refuse(
                state, "MANDATE_TERM_NOT_GRANTABLE",
                f"{cls} is a restricted class, default EXCLUDED "
                f"from every mandate in P0 (spec 7.5)")
        if cls not in FIELD_CLASSES:
            return refuse(state, "MANDATE_TERM_NOT_GRANTABLE",
                          f"field class {cls!r} is not grantable")
    if "FULL_CHART" in classes:
        # Restrictive reading of spec 6.3 governs (fix-round
        # adjudication of the 6.3 vs 13.3 tension, flagged as a
        # spec errata in README/manifest): any FULL_CHART grant
        # requires a separately counsel-reviewed mandate class
        # and NONE ships in P0 — so FULL_CHART is not grantable
        # to ANY P0 mandate, whatever its purposes.
        return refuse(
            state, "MANDATE_TERM_NOT_GRANTABLE",
            "FULL_CHART ships in no P0 mandate: any grant "
            "requires a separately counsel-reviewed mandate "
            "class, and none ships in P0 (spec 6.3)")
    if "CLINICAL_CONTEXT_LIMITED" in classes and not (
            set(purposes) & set(CLINICAL_CONTEXT_PURPOSES)):
        return refuse(
            state, "MANDATE_TERM_NOT_GRANTABLE",
            "CLINICAL_CONTEXT_LIMITED is grantable only to "
            "ENCOUNTER_SUPPORT / DOCUMENTATION purposes")
    parse_time(payload["expiry"], "expiry")
    mandate_ref = payload.get("mandate_id") or _tid("MND")
    record = dict(payload)
    record.pop("signature", None)
    record.update({"mandate_id": mandate_ref,
                   "effective_instant": now.isoformat(),
                   "signature_verified": True})
    state["mandates"][mandate_ref] = record
    return verdict(True, {"mandate_ref": mandate_ref,
                          "effective_instant":
                          record["effective_instant"]},
                   mandate_ref=mandate_ref, ts=now.isoformat())


def mandate_get(state, args):
    now = _now(args.get("now"))
    ref = require_ref_param(args.get("mandate_ref"), "mandate_ref")
    try:
        mandate = _mandate_live(state, ref, now)
    except Refusal as r:
        return refuse(state, r.refusal_class, r.detail,
                      mandate_ref=ref, ts=now.isoformat())
    return verdict(True, {"mandate": mandate}, mandate_ref=ref,
                   ts=now.isoformat())


# ----------------------------------------------------- policy packs
def load_packs():
    """Packs are versioned counsel-signed DATA (spec section 7):
    read fresh from the pack store on every evaluation — code
    holds no jurisdiction rule of its own."""
    return _fixtures("policy_packs.json")["packs"]


def pack_for(jurisdiction):
    for pack in load_packs():
        if pack["jurisdiction"] == jurisdiction:
            return pack
    return None


def _pack_gate(pack, jurisdiction, now):
    if pack is None:
        raise Refusal("JURISDICTION_NOT_IN_PACK",
                      f"no policy pack covers {jurisdiction}")
    if pack["state"] not in ("SIGNED", "IN_FORCE") or \
            not pack.get("counsel_signoff_ref"):
        raise Refusal("POLICY_PACK_UNSIGNED",
                      f"pack {pack['pack_id']} v{pack['version']} "
                      f"is {pack['state']} with no counsel sign-off "
                      f"in force; the gate does not evaluate")
    if parse_time(pack["effective_until"], "effective_until") <= now:
        raise Refusal("POLICY_PACK_STALE",
                      f"pack {pack['pack_id']} v{pack['version']} "
                      f"effective interval ended "
                      f"{pack['effective_until']}")
    return pack


def consent_set_required(state, args):
    now = _now(args.get("now"))
    jurisdiction = require_ref_param(
        args.get("jurisdiction"), "jurisdiction")
    visit_type = require_ref_param(args.get("visit_type"),
                                   "visit_type")
    pack = pack_for(jurisdiction)
    try:
        _pack_gate(pack, jurisdiction, now)
    except Refusal as r:
        return refuse(state, r.refusal_class, r.detail,
                      pack_version=pack["version"] if pack else None,
                      ts=now.isoformat())
    visit = pack["visit_types"].get(visit_type)
    if visit is None:
        return refuse(state, "JURISDICTION_NOT_IN_PACK",
                      f"pack {pack['pack_id']} declares no visit "
                      f"type {visit_type} for {jurisdiction}",
                      pack_version=pack["version"],
                      ts=now.isoformat())
    required = list(visit["consent_set"])
    recording = bool(args.get("recording_requested"))
    if recording:
        required = required + ["recording"]
    return verdict(True, {
        "jurisdiction": jurisdiction, "visit_type": visit_type,
        "required_consents": required,
        "recording_consent_model": pack["recording"][
            "consent_model"],
        "ai_disclosure_required": pack["recording"][
            "ai_disclosure_required"],
        "synthetic_pack": bool(pack.get("synthetic"))},
        pack_version=pack["version"], ts=now.isoformat())


# -------------------------------------------------- license (Lock A1)
def license_verify_at_encounter(state, args):
    """Re-verified PER ENCOUNTER from the roster feed, read fresh
    on every call — a prior pass is evidence, never an input cache
    (spec 2.1). Source + as-of ride on every answer."""
    now = _now(args.get("now"))
    clinician = require_ref_param(args.get("clinician_id"),
                                  "clinician_id")
    attested = require_ref_param(args.get("patient_state"),
                                 "patient_state")
    profession = require_ref_param(args.get("profession_class"),
                                   "profession_class")
    feed = _fixtures("roster_feed.json")
    fact = None
    for entry in feed["facts"]:
        if (entry["clinician_id"] == clinician
                and entry["profession_class"] == profession):
            if entry["state"] == attested:
                fact = entry
    state["seq"] += 1
    verification = {"verification_id": _tid("LIC"),
                    "clinician_id": clinician, "state": attested,
                    "profession_class": profession,
                    "visit_type": args.get("visit_type"),
                    "encounter_ref": args.get("encounter_ref"),
                    "as_of": now.isoformat()}
    if clinician == "CLIN-FEED-DOWN" or fact is None and \
            clinician not in {f["clinician_id"]
                              for f in feed["facts"]}:
        verification.update({"status": "UNVERIFIED", "source": None})
        return refuse(state, "LICENSE_STATE_UNVERIFIED",
                      "roster feed returned no license fact; the "
                      "gate fails closed and never invents one",
                      mandate_ref=args.get("mandate_ref"),
                      ts=now.isoformat())
    if fact is None:
        verification.update({"status": "NOT_COVERED",
                             "source": feed["feed_source"]})
        cited = {"value": f"no {profession} license fact for "
                          f"{attested}", "source": feed["feed_source"],
                   "as_of": now.isoformat()}
        return refuse(state, "JURISDICTION_MISMATCH",
                      "clinician holds no license/privilege fact "
                      "covering the patient's attested state",
                      cited_fact=cited,
                      mandate_ref=args.get("mandate_ref"),
                      ts=now.isoformat())
    status = fact["status"]
    if fact.get("lapses_at") and \
            parse_time(fact["lapses_at"], "lapses_at") <= now:
        status = fact.get("status_after_lapse", "LAPSED")
    verification.update({"status": status, "source": fact["source"],
                         "fact_as_of": fact["as_of"]})
    cited = {"value": f"{profession} license in {attested}: "
                      f"{status}", "source": fact["source"],
             "as_of": fact["as_of"]}
    if status != "ACTIVE":
        return refuse(state, "JURISDICTION_MISMATCH",
                      f"license fact at encounter time is {status}",
                      cited_fact=cited,
                      mandate_ref=args.get("mandate_ref"),
                      ts=now.isoformat())
    pack = pack_for(attested)
    return verdict(True, {"verification": verification,
                          "covered": True},
                   cited_fact=cited,
                   mandate_ref=args.get("mandate_ref"),
                   pack_version=pack["version"] if pack else None,
                   ts=now.isoformat())


# ------------------------------------------- access ledger (Lock C)
def seal_access(state, agent_id, patient_ref, requested, returned,
                purpose, verdict_class, mandate_ref, ts=None,
                practice_id=None):
    """Every PHI touch — granted or refused — seals a section
    164.312(b)-shaped, hash-chained access record held by the
    practice. Records are PRACTICE-SCOPED: each record carries
    its practice_id and chains within that practice's own chain
    (prev_hash = the practice's previous record, GENESIS at its
    head), so a practice's exported pack is a complete, verifiable
    chain containing ONLY that practice's records (tenant
    isolation, spec 11.2). The ledger is append-only; no tool
    truncates, rewrites, or backfills it."""
    scoped = [r for r in state["ledger"]
              if r.get("practice_id") == practice_id]
    prev = scoped[-1]["hash"] if scoped else "GENESIS"
    record = {"record_id": _tid("ACC"), "agent_id": agent_id,
              "patient_ref": patient_ref,
              "practice_id": practice_id,
              "classes_requested": list(requested),
              "classes_returned": list(returned),
              "purpose": purpose, "verdict": verdict_class,
              "mandate_ref": mandate_ref, "ts": ts or now_iso(),
              "prev_hash": prev}
    record["hash"] = sha(canonical_json(
        {k: record[k] for k in record if k != "hash"}))
    state["ledger"].append(record)
    return record


def verify_chain(records):
    prev = "GENESIS"
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            return {"ok": False, "failing_index": i,
                    "failing_record": None,
                    "reason": "record element is not an object"}
        if record.get("prev_hash") != prev:
            return {"ok": False, "failing_index": i,
                    "failing_record": record.get("record_id"),
                    "reason": "prev_hash break"}
        expect = sha(canonical_json(
            {k: record[k] for k in record if k != "hash"}))
        if record.get("hash") != expect:
            return {"ok": False, "failing_index": i,
                    "failing_record": record.get("record_id"),
                    "reason": "hash mismatch (record altered)"}
        prev = record["hash"]
    return {"ok": True, "records": len(records)}


def _patient(patient_ref):
    for patient in _fixtures("patients.json")["patients"]:
        if patient["patient_ref"] == patient_ref:
            return patient
    return None


def _phi_guard(state, args, patient, purpose_required=True):
    """Shared Lock C entry: purpose from the closed vocabulary,
    mandate live, tenant match. Returns (mandate, refusal|None)."""
    now = _now(args.get("now"))
    purpose = args.get("purpose")
    if purpose_required and purpose not in PURPOSES:
        return None, refuse(
            state, "PURPOSE_NOT_DECLARED",
            "no purpose declared from the closed vocabulary; "
            "there is no default purpose", ts=now.isoformat())
    mandate_ref = args.get("mandate_ref")
    if not mandate_ref:
        return None, refuse(state, "MANDATE_NOT_FOUND",
                            "no mandate ref supplied",
                            ts=now.isoformat())
    try:
        mandate = _mandate_live(state, mandate_ref, now)
    except Refusal as r:
        return None, refuse(state, r.refusal_class, r.detail,
                            mandate_ref=mandate_ref,
                            ts=now.isoformat())
    if purpose_required and purpose not in mandate["purpose_set"]:
        return None, refuse(
            state, "FIELD_CLASS_NOT_GRANTED",
            f"purpose {purpose} is outside the acting mandate",
            mandate_ref=mandate_ref, ts=now.isoformat())
    if patient is not None and \
            patient["practice_id"] != mandate["practice_id"]:
        return None, refuse(
            state, "FIELD_CLASS_NOT_GRANTED",
            "cross-tenant read refused: patient ref belongs to a "
            "different practice than the acting mandate",
            mandate_ref=mandate_ref, ts=now.isoformat())
    return mandate, None


def _seal_phi_read(state, args, patient, requested, returned,
                   verdict_class, default_agent="agent"):
    """Seal a PHI-read outcome under the CALLER's practice scope.
    A cross-tenant refusal is additionally sealed under the
    PATIENT's practice scope (spec H-15: the refusal appears in
    both tenants' audit views) — as a separate record in that
    practice's own chain, never by sharing one pack: each
    practice's pack contains only its own records."""
    now = _now(args.get("now"))
    mandate_ref = args.get("mandate_ref")
    mandate_rec = state["mandates"].get(mandate_ref) \
        if mandate_ref else None
    caller_practice = mandate_rec["practice_id"] if mandate_rec \
        else (patient["practice_id"] if patient else None)
    agent_id = mandate_rec["agent_id"] if mandate_rec \
        else default_agent
    if patient is not None and mandate_rec is not None and \
            patient["practice_id"] != caller_practice and \
            verdict_class != "GRANTED":
        seal_access(state, agent_id, patient["patient_ref"],
                    requested, [], args.get("purpose"),
                    verdict_class, mandate_ref,
                    ts=now.isoformat(),
                    practice_id=patient["practice_id"])
    return seal_access(state, agent_id,
                       patient["patient_ref"] if patient
                       else args.get("patient_ref"),
                       requested, returned, args.get("purpose"),
                       verdict_class, mandate_ref,
                       ts=now.isoformat(),
                       practice_id=caller_practice)


# ------------------------------------------------- Lock A gate core
def _clinical_screen(state, args, where):
    text = canonical_json(args).lower()
    for pattern in CLINICAL_PATTERNS:
        if pattern in text:
            state["clinical_queue"].append(
                {"queued_at": now_iso(), "where": where,
                 "request": args, "pattern": pattern,
                 "routed_to": "treating_clinician_queue"})
            return refuse(
                state, "CLINICAL_REQUEST",
                "request asks for a clinical determination; "
                "returned zero clinical content and routed intact "
                "to the treating clinician queue (spec 6.5)")
    return None


def _validate_gate_draft(draft):
    """Reference/container guards for gate inputs, applied as a
    class to every gate path (gate_check / schedule / start):
    consent_artifacts must be an array of objects carrying a
    string consent_type (and a string participant_ref when
    present); participants must be an array of strings. A
    string/int artifact or participant is refused BY NAME —
    never subscripted or hashed into a TypeError."""
    artifacts = draft.get("consent_artifacts", [])
    require_container_param(artifacts, "consent_artifacts",
                            "array")
    for i, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict) or \
                not isinstance(artifact.get("consent_type"), str):
            raise ToolError(
                f"CONSENT_ARTIFACT_TYPE_INVALID: "
                f"consent_artifacts[{i}] must be an object with "
                f"a string consent_type (got "
                f"{type(artifact).__name__}); refused by name")
        if "participant_ref" in artifact and not isinstance(
                artifact["participant_ref"], str):
            raise ToolError(
                f"CONSENT_ARTIFACT_TYPE_INVALID: "
                f"consent_artifacts[{i}].participant_ref must be "
                f"a string; refused by name")
    participants = draft.get("participants", [])
    require_container_param(participants, "participants", "array")
    require_string_elements(participants, "participants")
    return draft


def _seal_gate_refusal(state, draft, mandate, gate_out, phase, now):
    """Gate refusals are auditable events (spec 10.6/10.2): a
    refused gate run seals a section 164.312(b)-shaped access
    record in the acting practice's ledger scope, and the
    verdict carries its ref. A refused booking attempt therefore
    leaves a sealed trace, not just a transient response."""
    record = seal_access(
        state, mandate["agent_id"], draft.get("patient_ref"),
        [], [], draft.get("purpose", "ENCOUNTER_SUPPORT"),
        gate_out["refusal_class"], mandate["mandate_id"],
        ts=now.isoformat(), practice_id=mandate["practice_id"])
    gate_out["access_record_ref"] = record["record_id"]
    gate_out["data"] = {**gate_out.get("data", {}),
                        "gate_phase": phase,
                        "sealed_access_record": record["record_id"]}
    return record


def run_gate(state, draft, mandate, now, phase):
    """Full Lock A evaluation: A1 license (fresh) x A2 consent set
    (counsel-signed pack) x A3 mandate. Returns a verdict dict."""
    _validate_gate_draft(draft)
    clinician = draft["clinician_id"]
    attested = draft["patient_state"]
    visit_type = draft["visit_type"]
    pack = pack_for(attested)
    try:
        _pack_gate(pack, attested, now)
    except Refusal as r:
        return refuse(state, r.refusal_class, r.detail,
                      mandate_ref=mandate["mandate_id"],
                      pack_version=pack["version"] if pack else None,
                      ts=now.isoformat())
    lic = license_verify_at_encounter(state, {
        "clinician_id": clinician, "patient_state": attested,
        "profession_class": draft.get("profession_class", "MD"),
        "visit_type": visit_type, "now": now.isoformat(),
        "mandate_ref": mandate["mandate_id"]})
    if not lic["ok"]:
        out = dict(lic)
        out["data"] = {"failing_check": "A1", "phase": phase}
        return out
    if visit_type not in mandate["visit_types"]:
        return refuse(state, "VISIT_TYPE_OUTSIDE_MANDATE",
                      f"visit type {visit_type} is outside the "
                      f"acting mandate", mandate_ref=mandate[
                          "mandate_id"],
                      pack_version=pack["version"],
                      ts=now.isoformat())
    visit_pack = pack["visit_types"].get(visit_type)
    if visit_pack is None:
        return refuse(state, "JURISDICTION_NOT_IN_PACK",
                      f"pack {pack['pack_id']} declares no visit "
                      f"type {visit_type} for {attested}",
                      mandate_ref=mandate["mandate_id"],
                      pack_version=pack["version"],
                      ts=now.isoformat())
    required = list(visit_pack["consent_set"])
    captured = {a.get("consent_type") for a in
                draft.get("consent_artifacts", [])}
    missing = [c for c in required if c not in captured]
    if missing:
        return refuse(state, "CONSENT_SET_INCOMPLETE",
                      f"consent set for {attested} x {visit_type} "
                      f"is incomplete; missing {missing}",
                      cited_fact={"value": missing,
                                  "source": f"policy pack "
                                            f"{pack['pack_id']} "
                                            f"v{pack['version']}",
                                  "as_of": pack["effective_from"]},
                      mandate_ref=mandate["mandate_id"],
                      pack_version=pack["version"],
                      ts=now.isoformat())
    if draft.get("recording_requested"):
        participants = draft.get("participants", [])
        recorded = {a.get("participant_ref") for a in
                    draft.get("consent_artifacts", [])
                    if a.get("consent_type") == "recording"}
        unaccounted = [p for p in participants if p not in recorded]
        if unaccounted:
            return refuse(
                state, "RECORDING_CONSENT_MISSING",
                f"recording requires affirmative consent from "
                f"EVERY participant; unaccounted: {unaccounted}. "
                f"Recording does not start",
                mandate_ref=mandate["mandate_id"],
                pack_version=pack["version"], ts=now.isoformat())
    return verdict(True, {"failing_check": None, "phase": phase,
                          "license_verification":
                          lic["data"]["verification"],
                          "consents_required": required,
                          "recording_state": "RECORDING_ON" if
                          draft.get("recording_requested") else
                          "RECORDING_OFF"},
                   cited_fact=lic["cited_fact"],
                   mandate_ref=mandate["mandate_id"],
                   pack_version=pack["version"],
                   ts=now.isoformat())


def _gate_inputs(state, args):
    now = _now(args.get("now"))
    draft = require_container_param(args.get("encounter_draft"),
                                    "encounter_draft", "object")
    for field in ("clinician_id", "patient_ref", "patient_state",
                  "visit_type", "mandate_ref"):
        if field not in draft:
            raise ToolError(f"ENCOUNTER_FIELD_MISSING: {field}")
        require_ref_param(draft[field], f"encounter_draft.{field}")
    try:
        mandate = _mandate_live(state, draft["mandate_ref"], now)
    except Refusal as r:
        return now, draft, None, refuse(
            state, r.refusal_class, r.detail,
            mandate_ref=draft["mandate_ref"], ts=now.isoformat())
    if mandate["practice_id"] != draft.get("practice_id",
                                           mandate["practice_id"]):
        return now, draft, None, refuse(
            state, "JURISDICTION_MISMATCH",
            "encounter practice does not match mandate practice",
            mandate_ref=draft["mandate_ref"], ts=now.isoformat())
    return now, draft, mandate, None


def encounter_gate_check(state, args):
    """Dry-run Lock A: any number of times, zero booking/state
    change — but a PHI-touching dry-run refusal still seals an
    access record (spec 10.6: Gate dry-runs that touch PHI are
    auditable events)."""
    now, draft, mandate, err = _gate_inputs(state, args)
    if err:
        return err
    out = run_gate(state, draft, mandate, now, "dry_run")
    out["data"]["dry_run"] = True
    if not out["ok"]:
        _seal_gate_refusal(state, draft, mandate, out, "dry_run",
                           now)
    return out


def encounter_schedule(state, args):
    """Books ONLY on a gate pass at schedule time, against the
    booking-time attestation. A failed gate books nothing."""
    now, draft, mandate, err = _gate_inputs(state, args)
    if err:
        return err
    gate = run_gate(state, draft, mandate, now, "booking")
    if not gate["ok"]:
        gate["data"]["booked"] = False
        _seal_gate_refusal(state, draft, mandate, gate, "booking",
                           now)
        return gate
    encounter_id = _tid("ENC")
    encounter = {"encounter_id": encounter_id,
                 "practice_id": mandate["practice_id"],
                 "clinician_id": draft["clinician_id"],
                 "patient_ref": draft["patient_ref"],
                 "visit_type": draft["visit_type"],
                 "mandate_id": mandate["mandate_id"],
                 "state": "SCHEDULED",
                 "booking_attestation": {
                     "state": draft["patient_state"],
                     "source": draft.get("attestation_source",
                                         "patient-stated"),
                     "attested_at": now.isoformat(),
                     "phase": "booking"},
                 "consent_artifacts": draft.get(
                     "consent_artifacts", []),
                 "participants": draft.get("participants", []),
                 "recording_requested": bool(draft.get(
                     "recording_requested")),
                 "profession_class": draft.get(
                     "profession_class", "MD")}
    pack = {"pack_id": _tid("EPK"), "encounter_id": encounter_id,
            "gate_verdicts": [{"phase": "booking", "verdict": gate}],
            "consent_artifacts": encounter["consent_artifacts"],
            "access_record_refs": [],
            "pack_versions": [gate["policy_pack_version"]],
            "pin_statement": "NO_PIN_RECORD"}
    state["encounters"][encounter_id] = encounter
    state["packs"][encounter_id] = pack
    return verdict(True, {"encounter_id": encounter_id,
                          "encounter_state": "SCHEDULED",
                          "gate": gate},
                   mandate_ref=mandate["mandate_id"],
                   pack_version=gate["policy_pack_version"],
                   ts=now.isoformat())


def encounter_start_gate(state, args):
    """Start authorization: FRESH attestation + FULL A1+A2+A3
    re-run. A booking-time pass confers zero authority here; a
    location change booking->start is the normal trigger case."""
    now = _now(args.get("now"))
    encounter_id = require_ref_param(args.get("encounter_ref"),
                                     "encounter_ref")
    encounter = state["encounters"].get(encounter_id)
    if encounter is None:
        return refuse(state, "ENCOUNTER_NOT_FOUND",
                      f"no encounter {encounter_id}",
                      ts=now.isoformat())
    fresh_state_attested = require_ref_param(
        args.get("patient_state"), "patient_state")
    try:
        mandate = _mandate_live(state, encounter["mandate_id"], now)
    except Refusal as r:
        out = refuse(state, r.refusal_class, r.detail,
                     mandate_ref=encounter["mandate_id"],
                     ts=now.isoformat())
        mandate_rec = state["mandates"].get(
            encounter["mandate_id"], {})
        record = seal_access(
            state, mandate_rec.get("agent_id", "agent"),
            encounter["patient_ref"], [], [],
            "ENCOUNTER_SUPPORT", r.refusal_class,
            encounter["mandate_id"], ts=now.isoformat(),
            practice_id=mandate_rec.get("practice_id"))
        out["access_record_ref"] = record["record_id"]
        state["packs"][encounter_id]["access_record_refs"].append(
            record["record_id"])
        state["packs"][encounter_id]["gate_verdicts"].append(
            {"phase": "start", "verdict": out})
        return out
    draft = {"clinician_id": encounter["clinician_id"],
             "patient_ref": encounter["patient_ref"],
             "patient_state": fresh_state_attested,
             "visit_type": encounter["visit_type"],
             "mandate_ref": encounter["mandate_id"],
             "profession_class": encounter["profession_class"],
             "consent_artifacts": args.get(
                 "consent_artifacts",
                 encounter["consent_artifacts"]),
             "participants": encounter["participants"],
             "recording_requested":
             encounter["recording_requested"]}
    gate = run_gate(state, draft, mandate, now, "start")
    gate["data"]["location_changed"] = (
        fresh_state_attested !=
        encounter["booking_attestation"]["state"])
    gate["data"]["start_attestation"] = {
        "state": fresh_state_attested,
        "source": args.get("attestation_source", "patient-stated"),
        "attested_at": now.isoformat(), "phase": "start"}
    state["packs"][encounter_id]["gate_verdicts"].append(
        {"phase": "start", "verdict": gate})
    if gate["ok"]:
        encounter["state"] = "STARTED"
        encounter["start_attestation"] = gate["data"][
            "start_attestation"]
        gate["data"]["encounter_state"] = "STARTED"
    else:
        gate["data"]["encounter_state"] = encounter["state"]
        record = _seal_gate_refusal(state, draft, mandate, gate,
                                    "start", now)
        state["packs"][encounter_id]["access_record_refs"].append(
            record["record_id"])
    return gate


def encounter_pack_get(state, args):
    encounter_id = require_ref_param(args.get("encounter_ref"),
                                     "encounter_ref")
    pack = state["packs"].get(encounter_id)
    if pack is None:
        return refuse(state, "ENCOUNTER_NOT_FOUND",
                      f"no encounter pack for {encounter_id}")
    return verdict(True, {"encounter_pack": pack,
                          "encounter_state":
                          state["encounters"][encounter_id][
                              "state"]})


# ------------------------------------------------ intake (read-only)
def intake_template_get(state, args):
    practice = require_ref_param(args.get("practice_id"),
                                 "practice_id")
    visit_type = require_ref_param(args.get("visit_type"),
                                   "visit_type")
    for entry in _fixtures("patients.json")["intake_templates"]:
        if entry["practice_id"] == practice and \
                entry["visit_type"] == visit_type:
            return verdict(True, {"template": entry["template"],
                                  "note": "administrative fields "
                                          "only; Meridian authors "
                                          "no clinical-answer "
                                          "content"})
    return refuse(state, "TEMPLATE_NOT_FOUND",
                  f"no intake template for {practice} x "
                  f"{visit_type}")


def intake_status_get(state, args):
    clinical = _clinical_screen(state, args, "intake_status_get")
    if clinical:
        return clinical
    intake_ref = require_ref_param(args.get("intake_ref"),
                                   "intake_ref")
    intake = None
    for entry in _fixtures("patients.json")["intakes"]:
        if entry["intake_ref"] == intake_ref:
            intake = entry
    if intake is None:
        return refuse(state, "TEMPLATE_NOT_FOUND",
                      f"no intake {intake_ref}")
    patient = _patient(intake["patient_ref"])
    mandate, err = _phi_guard(state, args, patient)
    record = _seal_phi_read(
        state, args, patient, ["IDENTITY_CONTACT"],
        [] if err else ["IDENTITY_CONTACT"],
        err["refusal_class"] if err else "GRANTED",
        default_agent=args.get("agent_id", "agent"))
    if err:
        err["access_record_ref"] = record["record_id"]
        return err
    return verdict(True, {"intake_ref": intake_ref,
                          "sections": intake["sections"],
                          "note": "completion state as recorded, "
                                  "source-labeled; no inference, "
                                  "no eligibility or coverage "
                                  "determination"},
                   mandate_ref=mandate["mandate_id"],
                   access_record_ref=record["record_id"])


# -------------------------------------------------- notes (Lock B)
CANON_PROFILE = "meridian-canon-v1"


def note_fingerprint(draft) -> str:
    """SHA-256 over the canonical serialization (profile
    meridian-canon-v1): sorted fields, whitespace/line-endings
    normalized, author + encounter + draft version bound into the
    hashed envelope. A profile change never rewrites a signed
    fingerprint."""
    content = draft["content"]
    if isinstance(content, str):
        normalized = "\n".join(
            line.strip() for line in
            content.replace("\r\n", "\n").replace("\r", "\n")
            .split("\n")).strip()
        body = {"text": normalized}
    else:
        body = require_container_param(content, "content", "object")
    envelope = {"profile": CANON_PROFILE, "body": body,
                "author_agent_id": draft["author_agent_id"],
                "encounter_id": draft["encounter_id"],
                "draft_version": draft["version"]}
    return sha(canonical_json(envelope))


def note_draft_create(state, args):
    """Creates a draft in the DRAFT STORE — cryptographically
    outside the record namespace. Every draft carries its standing
    status: UNSIGNED_DRAFT_NOT_RECORD. There is deliberately no
    tool in this surface that signs or finalizes a draft
    (spec 6.2)."""
    clinical = _clinical_screen(state, args, "note_draft_create")
    if clinical:
        return clinical
    encounter_id = require_ref_param(args.get("encounter_ref"),
                                     "encounter_ref")
    if encounter_id not in state["encounters"]:
        return refuse(state, "ENCOUNTER_NOT_FOUND",
                      f"no encounter {encounter_id}")
    edit_of = args.get("edit_of_draft_id")
    if edit_of:
        prior = state["drafts"].get(edit_of)
        if prior and prior.get("signed"):
            return refuse(
                state, "ADDENDUM_REQUIRED",
                "the target draft state is SIGNED and immutable; "
                "post-signature change is a new version via "
                "note_addendum_create, never an edit")
        if prior:
            prior["version"] += 1
            prior["content"] = args.get("content",
                                        prior["content"])
            prior["fingerprint"] = note_fingerprint(prior)
            return verdict(True, {
                "draft": prior,
                "standing_status": "UNSIGNED_DRAFT_NOT_RECORD"})
    draft_id = _tid("DRF")
    draft = {"draft_id": draft_id, "encounter_id": encounter_id,
             "author_agent_id": require_ref_param(
                 args.get("drafting_agent_id"), "drafting_agent_id"),
             "content": args.get("content", ""), "version": 1,
             "state": "DRAFT", "signed": False,
             "addendum_of": args.get("addendum_of"),
             "created_at": now_iso()}
    draft["fingerprint"] = note_fingerprint(draft)
    state["drafts"][draft_id] = draft
    return verdict(True, {"draft": draft,
                          "standing_status":
                          "UNSIGNED_DRAFT_NOT_RECORD",
                          "note": "draft lives OUTSIDE the record; "
                                  "no chart read returns it"})


def note_fingerprint_get(state, args):
    draft_id = require_ref_param(args.get("draft_ref"), "draft_ref")
    draft = state["drafts"].get(draft_id)
    if draft is None:
        return refuse(state, "DRAFT_NOT_FOUND",
                      f"no draft {draft_id}")
    return verdict(True, {"draft_ref": draft_id,
                          "fingerprint": note_fingerprint(draft),
                          "profile": CANON_PROFILE,
                          "draft_version": draft["version"]})


def note_sign_request(state, args):
    """Routes the EXACT fingerprint to the treating clinician for
    signature in the system of record. This tool signs NOTHING —
    signature is the clinician's act (spec 6.1 tool 13, 6.2)."""
    draft_id = require_ref_param(args.get("draft_ref"), "draft_ref")
    supplied = require_ref_param(args.get("fingerprint"),
                                 "fingerprint")
    clinician = require_ref_param(
        args.get("treating_clinician_ref"), "treating_clinician_ref")
    draft = state["drafts"].get(draft_id)
    if draft is None:
        return refuse(state, "DRAFT_NOT_FOUND",
                      f"no draft {draft_id}")
    current = note_fingerprint(draft)
    if supplied != current:
        return refuse(state, "NOTE_FINGERPRINT_MISMATCH",
                      "fingerprint supplied differs from the "
                      "current draft state; the draft moved after "
                      "the request was composed",
                      cited_fact={"value": current, "source":
                                  "draft store canonical hash",
                                  "as_of": now_iso()})
    request_id = _tid("SGR")
    state["sign_requests"][request_id] = {
        "request_id": request_id, "draft_id": draft_id,
        "fingerprint": current,
        "treating_clinician_ref": clinician,
        "state": "AWAITING_SIGNATURE", "requested_at": now_iso()}
    draft["state"] = "AWAITING_SIGNATURE"
    return verdict(True, {"sign_request_id": request_id,
                          "routed_fingerprint": current,
                          "routed_to": clinician,
                          "note": "routed only — the treating "
                                  "clinician signs in the system "
                                  "of record; no agent tool signs"})


# NOTE (spec 12.1 P0-5 + 6.2 product law): this shipped engine
# contains NO signing capability of any kind. Signature is the
# treating clinician's act in the system of record; the sign
# simulator that models it for tests is bench equipment living
# ONLY under tests/ as a test fixture — no product file defines,
# imports, or references it, and no code path in this engine can
# create a signed note or move a draft into signed state.


def note_signed_status_get(state, args):
    ref = require_ref_param(args.get("note_ref"), "note_ref")
    draft = state["drafts"].get(ref)
    note = state["signed_notes"].get(ref)
    if note is None and draft is not None and draft.get("signed"):
        note = state["signed_notes"][draft["signed_note_id"]]
    if note is not None:
        chain = [note]
        current = note
        while current.get("superseded_by"):
            current = state["signed_notes"][current[
                "superseded_by"]]
            chain.append(current)
        return verdict(True, {"status": "SIGNED", "note": note,
                              "chain": chain,
                              "superseded": bool(note.get(
                                  "superseded_by"))})
    if draft is not None:
        return verdict(True, {"status": "UNSIGNED_DRAFT",
                              "standing_status":
                              "UNSIGNED_DRAFT_NOT_RECORD",
                              "fingerprint": note_fingerprint(draft)})
    return refuse(state, "DRAFT_NOT_FOUND", f"no draft/note {ref}")


def note_addendum_create(state, args):
    """The ONLY post-signature change path: a NEW draft version
    chained to the signed original, citing its fingerprint. The
    addendum is itself a draft until the clinician signs it under
    the same pin rule; the original remains served as signed."""
    note_id = require_ref_param(args.get("signed_note_ref"),
                                 "signed_note_ref")
    note = state["signed_notes"].get(note_id)
    if note is None:
        return refuse(state, "DRAFT_NOT_FOUND",
                      f"no signed note {note_id}")
    out = note_draft_create(state, {
        "encounter_ref": note["encounter_id"],
        "content": args.get("content", ""),
        "drafting_agent_id": args.get("drafting_agent_id",
                                      "agent"),
        "addendum_of": note_id})
    if out["ok"]:
        out["data"]["cites_fingerprint"] = note[
            "signed_fingerprint"]
        out["data"]["addendum_for_note"] = note_id
    return out


def chart_record_read(state, args):
    """Internal record-read path used to prove Lock B invariant
    (i): record reads serve ONLY signed states. A draft ref asked
    through the record path returns UNSIGNED_DRAFT_NOT_RECORD and
    zero draft bytes (spec 13.2 H-7). Never an MCP tool."""
    ref = args.get("ref")
    if ref in state["drafts"] and ref not in state["signed_notes"]:
        return refuse(state, "UNSIGNED_DRAFT_NOT_RECORD",
                      "ref names a draft; drafts are outside the "
                      "record and are never served by a record read")
    note = state["signed_notes"].get(ref)
    if note is None:
        return refuse(state, "DRAFT_NOT_FOUND",
                      f"no signed note {ref}")
    return verdict(True, {"note": note})


# --------------------------------------------- PHI reads (Lock C)
def _projected_read(state, args, patient_ref, source_classes,
                    default_agent="agent"):
    """Server-side projection BEFORE serialization: the caller
    receives only field classes the acting mandate grants for the
    declared purpose. Restricted classes are never granted, never
    returned, and probing them has the same refusal shape as any
    ungranted class (spec 13.2 H-9/H-10)."""
    now = _now(args.get("now"))
    patient = _patient(patient_ref)
    if patient is None:
        record = _seal_phi_read(state, args, None, [], [],
                                "FIELD_CLASS_NOT_GRANTED",
                                default_agent=default_agent)
        out = refuse(state, "FIELD_CLASS_NOT_GRANTED",
                     "no patient record under that ref in this "
                     "tenant scope", mandate_ref=args.get(
                         "mandate_ref"), ts=now.isoformat())
        out["access_record_ref"] = record["record_id"]
        return out, None, None
    mandate, err = _phi_guard(state, args, patient)
    requested = args.get("requested_classes")
    if requested is not None:
        require_container_param(requested, "requested_classes",
                                "array")
        require_string_elements(requested, "requested_classes")
    else:
        requested = [c for c in source_classes]
    granted = set(mandate["field_classes"]) if mandate else set()
    if err is None and mandate is not None:
        purpose = args.get("purpose")
        if "CLINICAL_CONTEXT_LIMITED" in requested and \
                purpose not in CLINICAL_CONTEXT_PURPOSES:
            err = refuse(state, "FIELD_CLASS_NOT_GRANTED",
                         "CLINICAL_CONTEXT_LIMITED is grantable "
                         "only to ENCOUNTER_SUPPORT / DOCUMENTATION",
                         mandate_ref=mandate["mandate_id"],
                         ts=now.isoformat())
    returned = []
    if err is None:
        over = [c for c in requested if c not in granted]
        if over:
            err = refuse(state, "FIELD_CLASS_NOT_GRANTED",
                         f"field classes not granted to the acting "
                         f"mandate: {over}; tool parameters never "
                         f"widen a mandate",
                         mandate_ref=mandate["mandate_id"],
                         ts=now.isoformat())
    if err is None:
        returned = [c for c in requested if c in source_classes]
    record = _seal_phi_read(
        state, args, patient, requested, returned,
        err["refusal_class"] if err else "GRANTED",
        default_agent=default_agent)
    if err is not None:
        err["access_record_ref"] = record["record_id"]
        return err, None, record
    projected = {cls: patient["classes"][cls] for cls in returned
                 if cls in patient["classes"]}
    out = verdict(True, {"patient_ref": patient_ref,
                         "classes_returned": returned,
                         "context": projected},
                  mandate_ref=mandate["mandate_id"],
                  access_record_ref=record["record_id"],
                  ts=now.isoformat())
    return out, mandate, record


def patient_context_get(state, args):
    patient_ref = require_ref_param(args.get("patient_ref"),
                                    "patient_ref")
    patient = _patient(patient_ref)
    source = list(patient["classes"]) if patient else []
    out, _, _ = _projected_read(state, args, patient_ref, source)
    return out


def appointment_get(state, args):
    appointment_ref = require_ref_param(
        args.get("appointment_ref"), "appointment_ref")
    appointment = None
    for entry in _fixtures("patients.json")["appointments"]:
        if entry["appointment_ref"] == appointment_ref:
            appointment = entry
    if appointment is None:
        return refuse(state, "FIELD_CLASS_NOT_GRANTED",
                      "no appointment under that ref in this "
                      "tenant scope")
    scoped = dict(args)
    scoped.setdefault("requested_classes",
                      list(appointment["classes"]))
    require_container_param(scoped["requested_classes"],
                            "requested_classes", "array")
    require_string_elements(scoped["requested_classes"],
                            "requested_classes")
    patient = _patient(appointment["patient_ref"])
    mandate, err = _phi_guard(state, scoped, patient)
    now = _now(args.get("now"))
    returned = [] if err else [
        c for c in scoped["requested_classes"]
        if c in mandate["field_classes"]
        and c in appointment["classes"]]
    if err is None and len(returned) != len(
            scoped["requested_classes"]):
        err = refuse(state, "FIELD_CLASS_NOT_GRANTED",
                     "requested classes exceed the acting mandate",
                     mandate_ref=mandate["mandate_id"],
                     ts=now.isoformat())
        returned = []
    record = _seal_phi_read(
        state, scoped, patient, scoped["requested_classes"],
        returned, err["refusal_class"] if err else "GRANTED")
    if err is not None:
        err["access_record_ref"] = record["record_id"]
        return err
    return verdict(True, {
        "appointment_ref": appointment_ref,
        "classes_returned": returned,
        "appointment": {c: appointment["classes"][c]
                        for c in returned}},
        mandate_ref=mandate["mandate_id"],
        access_record_ref=record["record_id"], ts=now.isoformat())


# ------------------------------------------------- access pack tools
def access_pack_get(state, args):
    """Practice-held export: hash-chained records mapped to FHIR
    AuditEvent + Provenance shape. Audit reads declare
    AUDIT_REVIEW like any other read."""
    now = _now(args.get("now"))
    purpose = args.get("purpose")
    if purpose not in PURPOSES:
        # Undeclared (or off-vocabulary) purpose only.
        return refuse(state, "PURPOSE_NOT_DECLARED",
                      "access-pack reads must declare a purpose "
                      "from the closed vocabulary; audit reads "
                      "declare AUDIT_REVIEW", ts=now.isoformat())
    if purpose != "AUDIT_REVIEW":
        # Declared-but-wrong purpose for this tool: named
        # PURPOSE_NOT_GRANTED (spec-gap naming, flagged: the
        # 6.4 registry names PURPOSE_NOT_DECLARED only for the
        # undeclared case, so the mismatch class follows the
        # registry's *_NOT_GRANTED convention — Lock C parity
        # with _phi_guard's mandate-membership enforcement).
        return refuse(state, "PURPOSE_NOT_GRANTED",
                      f"purpose {purpose} is declared but does "
                      f"not grant access-pack reads; audit reads "
                      f"require AUDIT_REVIEW",
                      ts=now.isoformat())
    mandate_ref = args.get("mandate_ref")
    try:
        mandate = _mandate_live(state, mandate_ref, now)
    except Refusal as r:
        return refuse(state, r.refusal_class, r.detail,
                      mandate_ref=mandate_ref, ts=now.isoformat())
    if purpose not in mandate["purpose_set"]:
        return refuse(state, "PURPOSE_NOT_GRANTED",
                      f"purpose {purpose} is not in the acting "
                      f"mandate's purpose_set; mandate membership "
                      f"is enforced, not just the declared string",
                      mandate_ref=mandate_ref, ts=now.isoformat())
    if mandate["practice_id"] != require_ref_param(
            args.get("practice_id"), "practice_id"):
        return refuse(state, "FIELD_CLASS_NOT_GRANTED",
                      "access pack belongs to the mandate's own "
                      "practice only", mandate_ref=mandate_ref,
                      ts=now.isoformat())
    # Tenant isolation: a pack contains ONLY the requesting
    # practice's records — never the shared ledger's other
    # tenants' records (spec 11.2, H-15).
    records = [r for r in state["ledger"]
               if r.get("practice_id") == mandate["practice_id"]]
    patient_filter = args.get("patient_ref")
    if patient_filter:
        records = [r for r in records
                   if r["patient_ref"] == patient_filter]
    fhir = [{"resourceType": "AuditEvent",
             "agent": [{"who": {"identifier": {"value":
                                               r["agent_id"]}},
                        "requestor": False}],
             "entity": [{"what": {"identifier": {"value":
                                                 r["patient_ref"]}}}],
             "recorded": r["ts"],
             "outcomeDesc": r["verdict"],
             "purposeOfEvent": [{"text": r["purpose"]}],
             "meridian": {"record_id": r["record_id"],
                          "classes_requested":
                          r["classes_requested"],
                          "classes_returned":
                          r["classes_returned"],
                          "mandate_ref": r["mandate_ref"],
                          "hash": r["hash"],
                          "prev_hash": r["prev_hash"]}}
            for r in records]
    return verdict(True, {"records": records,
                          "fhir_audit_events": fhir,
                          "provenance": {"agent": "Eclipse "
                                                  "Meridian Core",
                                         "entity": "access pack "
                                                   "export"}},
                   mandate_ref=mandate_ref, ts=now.isoformat())


def access_pack_verify(state, args):
    """Offline verification of an exported pack: chain integrity
    + interval completeness. Gaps are FINDINGS, never silently
    passed (spec 9.3)."""
    pack = require_container_param(args.get("access_pack"),
                                   "access_pack", "object")
    records = require_container_param(pack.get("records"),
                                      "access_pack.records",
                                      "array")
    findings = []
    bad_elements = [i for i, r in enumerate(records)
                    if not isinstance(r, dict)]
    if bad_elements:
        findings.append(
            {"finding": "RECORD_TYPE_INVALID",
             "detail": f"records at indices {bad_elements} are "
                       f"not objects; verification refuses them "
                       f"by name, never dereferences them"})
        records = [r for r in records if isinstance(r, dict)]
    chain = verify_chain(records)
    if not chain["ok"]:
        findings.append(chain)
    expected = args.get("expected_interval")
    if expected:
        stamps = sorted(parse_time(r.get("ts"), "record.ts")
                        for r in records)
        if not stamps or stamps[0] > parse_time(
                expected["from"], "interval.from") or \
                stamps[-1] < parse_time(expected["to"],
                                        "interval.to"):
            findings.append(
                {"finding": "INTERVAL_INCOMPLETE",
                 "detail": "export does not cover the declared "
                           "interval; a missing interval is a "
                           "finding, never a silent pass"})
    return verdict(not findings,
                   {"chain_ok": chain["ok"], "findings": findings,
                    "records_checked": len(records)},
                   refusal_class=None if not findings else None,
                   detail="verification verdicts are findings, not "
                          "refusals (spec 6.1 tool 19)")


# ------------------------------------------- Bridge (BAA gate, s.8)
def bridge_configure(state, args):
    """Deployment registration (admin surface, not an MCP tool):
    records the BAA artifact + subprocessor flow-down inventory
    for a deployment. P0 default: NO BAA on file."""
    deployment = require_ref_param(args.get("deployment_id"),
                                   "deployment_id")
    state["deployments"][deployment] = {
        "deployment_id": deployment,
        "baa_artifact_ref": args.get("baa_artifact_ref"),
        "flow_down_inventory": args.get("flow_down_inventory", []),
        "path_components": args.get("path_components", [])}
    return state["deployments"][deployment]


def _baa_gate(state, deployment_id):
    deployment = state["deployments"].get(deployment_id)
    if deployment is None or not deployment.get(
            "baa_artifact_ref"):
        raise Refusal("BAA_REQUIRED",
                      "no executed BAA artifact on file for this "
                      "deployment; Bridge runs sandbox/synthetic "
                      "only. There is no break-glass mode")
    missing = [c for c in deployment.get("path_components", [])
               if c not in deployment.get("flow_down_inventory",
                                          [])]
    if missing:
        raise Refusal("BAA_REQUIRED",
                      f"subprocessor flow-down inventory is "
                      f"missing {missing}; a missing flow-down is "
                      f"BAA_REQUIRED, same as no BAA")
    return deployment


def bridge_sandbox_read(state, args):
    """P0 Bridge: HAPI FHIR sandbox adapter ONLY. Reads the local
    synthetic sandbox store; contains no network code path."""
    deployment = args.get("deployment_id", "P0-SANDBOX")
    registered = state["deployments"].get(deployment)
    if registered and registered.get("mode") == "live":
        return bridge_live_read(state, args)
    sandbox = _fixtures("fhir_sandbox.json")
    return verdict(True, {"mode": "sandbox",
                          "adapter": "hapi-fhir-r4-sandbox",
                          "resources": sandbox["resources"],
                          "note": "synthetic only; no live PHI "
                                  "route exists in P0"})


def bridge_live_read(state, args):
    """Any live-PHI operation passes the BAA gate FIRST (spec
    8.2, product law). With no executed BAA + complete flow-down
    inventory it returns BAA_REQUIRED and moves zero bytes."""
    deployment_id = require_ref_param(args.get("deployment_id"),
                                      "deployment_id")
    try:
        _baa_gate(state, deployment_id)
    except Refusal as r:
        return refuse(state, r.refusal_class, r.detail)
    return refuse(state, "BAA_REQUIRED",
                  "P0 ships no live adapter; the BAA gate passed "
                  "but no live-PHI route exists in this phase")


# Eclipse Meridian MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
