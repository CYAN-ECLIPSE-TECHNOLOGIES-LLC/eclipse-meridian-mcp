#!/usr/bin/env python3
# Eclipse Meridian MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Meridian Gate: standalone Lock A checker (spec 9.1), no Core required.

"""Encounter Gate (Meridian Gate) — standalone jurisdiction +
consent checker for practices not yet on Core.

Inputs: clinician license facts (with source) + patient attested
state + visit type + a counsel-signed policy pack. Output: the
same verdict object and the same refusal vocabulary as Core's
encounter_gate_check. Emits pre-booking verdicts only — it holds
no booking, no PHI store, no ledger, and confers no authority
(Core re-runs the gate at execution regardless).

Eclipse Meridian — governed telehealth operations —
jurisdiction-gated encounters, signed-note integrity, PHI access
evidence. Not a healthcare provider.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import meridian_engine as engine  # noqa: E402


def gate_check(license_facts, pack, attested_state, visit_type,
               consent_types_captured, recording_requested=False,
               participants=(), recording_consents=(), now=None):
    """Pure Lock A evaluation over caller-supplied facts."""
    now_dt = engine._now(now)
    try:
        engine._pack_gate(pack, attested_state, now_dt)
    except engine.Refusal as r:
        return engine.refuse({}, r.refusal_class, r.detail,
                             pack_version=pack.get("version") if pack
                             else None, ts=now_dt.isoformat())
    fact = None
    for entry in license_facts:
        if entry.get("state") == attested_state:
            fact = entry
    if fact is None:
        return engine.refuse(
            {}, "LICENSE_STATE_UNVERIFIED",
            "supplied license facts contain no fact for the "
            "attested state; fail closed",
            pack_version=pack["version"], ts=now_dt.isoformat())
    status = fact.get("status")
    if fact.get("lapses_at") and engine.parse_time(
            fact["lapses_at"], "lapses_at") <= now_dt:
        status = fact.get("status_after_lapse", "LAPSED")
    cited = {"value": f"license in {attested_state}: {status}",
             "source": fact.get("source"), "as_of": fact.get("as_of")}
    if status != "ACTIVE":
        return engine.refuse(
            {}, "JURISDICTION_MISMATCH",
            "license fact does not cover the attested state at "
            "encounter time", cited_fact=cited,
            pack_version=pack["version"], ts=now_dt.isoformat())
    visit = pack["visit_types"].get(visit_type)
    if visit is None:
        return engine.refuse(
            {}, "JURISDICTION_NOT_IN_PACK",
            f"pack declares no visit type {visit_type}",
            pack_version=pack["version"], ts=now_dt.isoformat())
    missing = [c for c in visit["consent_set"]
               if c not in consent_types_captured]
    if missing:
        return engine.refuse(
            {}, "CONSENT_SET_INCOMPLETE",
            f"consent set incomplete; missing {missing}",
            cited_fact={"value": missing,
                        "source": f"policy pack {pack['pack_id']} "
                                  f"v{pack['version']}",
                        "as_of": pack["effective_from"]},
            pack_version=pack["version"], ts=now_dt.isoformat())
    if recording_requested:
        unaccounted = [p for p in participants
                       if p not in recording_consents]
        if unaccounted:
            return engine.refuse(
                {}, "RECORDING_CONSENT_MISSING",
                f"every-participant recording consent incomplete; "
                f"unaccounted: {unaccounted}",
                pack_version=pack["version"],
                ts=now_dt.isoformat())
    return engine.verdict(
        True, {"advisory": True,
               "note": "pre-booking verdict only; Core re-runs the "
                       "gate at execution regardless"},
        cited_fact=cited, pack_version=pack["version"],
        ts=now_dt.isoformat())


def main(argv):
    if len(argv) != 2:
        print("usage: encounter_gate.py <input.json>")
        return 2
    payload = json.loads(Path(argv[1]).read_text())
    pack = engine.pack_for(payload["jurisdiction"])
    out = gate_check(payload["license_facts"], pack,
                     payload["jurisdiction"], payload["visit_type"],
                     payload.get("consent_types_captured", []),
                     payload.get("recording_requested", False),
                     payload.get("participants", []),
                     payload.get("recording_consents", []),
                     payload.get("now"))
    print(json.dumps(out, indent=1))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

# Eclipse Meridian MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
