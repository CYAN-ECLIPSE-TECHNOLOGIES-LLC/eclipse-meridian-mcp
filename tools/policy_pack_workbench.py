#!/usr/bin/env python3
# Eclipse Meridian MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Policy Pack Workbench: versioned counsel-signed DATA pack lifecycle (spec 9.4).

"""Policy Pack Workbench — jurisdiction rules as versioned,
counsel-signed DATA packs. Lifecycle: DRAFT -> COUNSEL_REVIEW ->
SIGNED -> IN_FORCE -> SUPERSEDED. Only SIGNED/IN_FORCE packs are
servable; Core refuses unsigned/stale packs by name.

The Workbench manages versions + sign-offs ONLY. It never authors
legal content: rule text enters only as counsel-supplied,
counsel-signed data — a pack cannot transition to SIGNED without
a counsel sign-off ref, and no field exists here to write a rule.

Eclipse Meridian — governed telehealth operations —
jurisdiction-gated encounters, signed-note integrity, PHI access
evidence. Not a healthcare provider.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import meridian_engine as engine  # noqa: E402

TRANSITIONS = {"DRAFT": ("COUNSEL_REVIEW",),
               "COUNSEL_REVIEW": ("SIGNED",),
               "SIGNED": ("IN_FORCE",),
               "IN_FORCE": ("SUPERSEDED",),
               "SUPERSEDED": ()}


def transition(pack, target, counsel_signoff_ref=None):
    current = pack["state"]
    if target not in TRANSITIONS.get(current, ()):
        return {"ok": False,
                "detail": f"illegal lifecycle transition "
                          f"{current} -> {target}"}
    if target == "SIGNED" and not (
            counsel_signoff_ref or pack.get("counsel_signoff_ref")):
        return {"ok": False,
                "detail": "SIGNED requires a counsel sign-off ref; "
                          "the Workbench never authors or implies "
                          "legal sign-off"}
    out = dict(pack)
    out["state"] = target
    if counsel_signoff_ref:
        out["counsel_signoff_ref"] = counsel_signoff_ref
    out["version_history"] = pack.get("version_history", []) + [
        {"from": current, "to": target,
         "version": pack["version"]}]
    return {"ok": True, "pack": out}


def servable(pack, now=None):
    """True only when Core may serve this pack at `now`."""
    try:
        engine._pack_gate(pack, pack["jurisdiction"],
                          engine._now(now))
        return True
    except engine.Refusal:
        return False


def main(argv):
    if len(argv) < 3:
        print("usage: policy_pack_workbench.py <packs.json> "
              "<check|transition> [args]")
        return 2
    data = json.loads(Path(argv[1]).read_text())
    packs = data["packs"]
    if argv[2] == "check":
        for pack in packs:
            print(f"{pack['pack_id']} v{pack['version']} "
                  f"{pack['state']} servable={servable(pack)}")
        return 0
    if argv[2] == "transition" and len(argv) >= 5:
        pack_id, target = argv[3], argv[4]
        ref = argv[5] if len(argv) > 5 else None
        for i, pack in enumerate(packs):
            if pack["pack_id"] == pack_id:
                out = transition(pack, target, ref)
                print(json.dumps(out, indent=1))
                if out["ok"]:
                    packs[i] = out["pack"]
                    Path(argv[1]).write_text(json.dumps(
                        data, indent=1))
                return 0 if out["ok"] else 1
        print(f"no pack {pack_id}")
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

# Eclipse Meridian MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
