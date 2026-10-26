#!/usr/bin/env python3
# Eclipse Meridian MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Meridian Pin: signed-state fingerprint + addendum-chain verifier (spec 9.2).

"""Note Pin Verifier (Meridian Pin; reserve name Eclipse
Chartline) — proves which exact state was signed (fingerprint
match), detects post-signature drift (served state != signed
fingerprint), and renders the addendum chain original -> each
signed addendum, in order. Read-only: never repairs, never
re-signs, never edits.

Eclipse Meridian — governed telehealth operations —
jurisdiction-gated encounters, signed-note integrity, PHI access
evidence. Not a healthcare provider.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import meridian_engine as engine  # noqa: E402


def verify_pin(chart_export):
    """chart_export: {signed_notes: [...], served: {note_id:
    content}} — recompute each signed fingerprint from the served
    content envelope and compare to the signed fingerprint."""
    findings = []
    chain = []
    notes = {n["note_id"]: n for n in chart_export["signed_notes"]}
    served = chart_export.get("served", {})
    roots = [n for n in notes.values()
             if not n.get("supersedes_ref")]
    for root in roots:
        current = root
        while current is not None:
            chain.append(current["note_id"])
            content = served.get(current["note_id"])
            if content is None:
                findings.append({
                    "note_id": current["note_id"],
                    "finding": "SERVED_STATE_MISSING"})
            else:
                probe = {"content": content,
                         "author_agent_id": current.get(
                             "author_agent_id", "agent"),
                         "encounter_id": current["encounter_id"],
                         "version": current["version"]}
                if engine.note_fingerprint(probe) != current[
                        "signed_fingerprint"]:
                    findings.append({
                        "note_id": current["note_id"],
                        "finding": "POST_SIGNATURE_DRIFT",
                        "detail": "served state does not match "
                                  "the signed fingerprint"})
            nxt = current.get("superseded_by")
            current = notes.get(nxt) if nxt else None
    return {"ok": not findings, "chain": chain,
            "findings": findings,
            "descriptor": engine.DESCRIPTOR}


def main(argv):
    if len(argv) != 2:
        print("usage: note_pin_verifier.py <chart-export.json>")
        return 2
    out = verify_pin(json.loads(Path(argv[1]).read_text()))
    print(json.dumps(out, indent=1))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

# Eclipse Meridian MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
