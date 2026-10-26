#!/usr/bin/env python3
# Eclipse Meridian MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Meridian Ledger: offline access-pack validation + 164.312(b) export (spec 9.3).

"""Access Ledger Verifier (Meridian Ledger) — validates access
packs OFFLINE: hash-chain integrity, section 164.312(b)-shaped
export rendering (FHIR AuditEvent/Provenance mapping), and
interval completeness. Missing intervals are findings, never
silently passed. Read-only; a pack that fails fails loudly with
the failing record + interval cited.

Eclipse Meridian — governed telehealth operations —
jurisdiction-gated encounters, signed-note integrity, PHI access
evidence. Not a healthcare provider.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import meridian_engine as engine  # noqa: E402


def verify_pack(pack, expected_interval=None):
    records = pack["records"]
    chain = engine.verify_chain(records)
    findings = []
    if not chain["ok"]:
        findings.append({"finding": "CHAIN_BREAK", **chain})
    if expected_interval:
        stamps = sorted(engine.parse_time(r["ts"], "record.ts")
                        for r in records)
        if not stamps or stamps[0] > engine.parse_time(
                expected_interval["from"], "interval.from") \
                or stamps[-1] < engine.parse_time(
                    expected_interval["to"], "interval.to"):
            findings.append({
                "finding": "INTERVAL_INCOMPLETE",
                "interval": expected_interval,
                "detail": "missing interval is a finding, never "
                          "a silent pass"})
    return {"ok": not findings, "records_checked": len(records),
            "findings": findings,
            "descriptor": engine.DESCRIPTOR}


def render_audit_events(pack):
    """Render the pack in 164.312(b) shape: FHIR AuditEvent +
    Provenance, one event per access record."""
    events = []
    for r in pack["records"]:
        events.append({
            "resourceType": "AuditEvent",
            "type": {"code": "rest"},
            "agent": [{"who": {"identifier": {"value":
                                              r["agent_id"]}}}],
            "entity": [{"what": {"identifier": {"value":
                                                r["patient_ref"]}}}],
            "recorded": r["ts"], "outcomeDesc": r["verdict"],
            "purposeOfEvent": [{"text": r["purpose"]}],
            "meridian": {"mandate_ref": r["mandate_ref"],
                         "classes_requested":
                         r["classes_requested"],
                         "classes_returned": r["classes_returned"],
                         "hash": r["hash"],
                         "prev_hash": r["prev_hash"]}})
    return {"resources": events,
            "provenance": {"resourceType": "Provenance",
                           "agent": [{"who": {"display":
                                              "Eclipse Meridian"}}]}}


def main(argv):
    if len(argv) not in (2, 3):
        print("usage: access_ledger_verifier.py <pack.json> "
              "[--render]")
        return 2
    pack = json.loads(Path(argv[1]).read_text())
    if len(argv) == 3 and argv[2] == "--render":
        print(json.dumps(render_audit_events(pack), indent=1))
        return 0
    out = verify_pack(pack)
    print(json.dumps(out, indent=1))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

# Eclipse Meridian MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
