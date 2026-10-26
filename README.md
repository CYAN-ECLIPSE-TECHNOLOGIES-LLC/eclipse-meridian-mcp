# Eclipse Meridian MCP

**Eclipse Meridian — governed telehealth operations — jurisdiction-gated encounters, signed-note integrity, PHI access evidence. Not a healthcare provider.**

P0 build, synthetic-only. Status: **built-uncertified / bench-pending** (Verity bench runs separately; P0 claim ceiling is CERTIFIED (simulator) and no result here claims it yet).

The fused mechanism (spec §2): an encounter executes only when licensure × consent set × mandate verify **at encounter time** against the patient's attested location (Lock A); a note enters the record only as the exact fingerprint the treating clinician signed, with AI drafts cryptographically outside the record until then — `UNSIGNED_DRAFT_NOT_RECORD` (Lock B); every PHI read returns only mandate-granted field classes and seals a §164.312(b)-shaped, hash-chained, practice-held access record, granted or refused (Lock C).

**Product law (§6.2): there is NO `note_finalize` tool — and no alias, synonym, or admin variant.** Signature is the treating clinician's act in the system of record. The agent documentation surface is: create draft → fingerprint → **request** signature → read status → addendum-as-new-version. Post-signature change is always a new version + addendum, never a silent edit. There is no prescribing surface in any phase.

## Surfaces

- **Meridian Core** (`server.py`, MCP over stdio, stdlib only) — exactly 19 tools per spec §6.1: `mandate_upsert`, `mandate_get`, `license_verify_at_encounter`, `consent_set_required`, `encounter_gate_check`, `encounter_schedule`, `encounter_start_gate`, `encounter_pack_get`, `intake_template_get`, `intake_status_get`, `note_draft_create`, `note_fingerprint_get`, `note_sign_request`, `note_signed_status_get`, `note_addendum_create`, `patient_context_get`, `appointment_get`, `access_pack_get`, `access_pack_verify`.
- **Meridian Bridge** (in `meridian_engine.py`) — HAPI FHIR R4 sandbox adapter only in P0 (local synthetic stand-in, no network code). **Refuses live PHI without an executed BAA + complete subprocessor flow-down inventory: `BAA_REQUIRED`, no break-glass.**
- **Standalone Tools** (`tools/`): Encounter Gate (§9.1), Note Pin Verifier (§9.2), Access Ledger Verifier (§9.3), Policy Pack Workbench (§9.4) — jurisdiction rules live in versioned, counsel-signed DATA packs (`data/policy_packs.json`, synthetic jurisdictions labeled synthetic), never in code constants.

## Guardrails baked in

- License re-verified per encounter, never cached; location change booking→start re-runs the full gate (`JURISDICTION_MISMATCH` / `CONSENT_SET_INCOMPLETE`).
- Recording requires affirmative consent from **every** participant or it doesn't start (`RECORDING_CONSENT_MISSING`); no ambient mode exists.
- 42 CFR Part 2 + minor-restricted classes are restricted classes, **default EXCLUDED** from every mandate; `FULL_CHART` is **not grantable to any P0 mandate** (see spec-errata flag below).
- Clinical requests return `CLINICAL_REQUEST` and route intact to the clinician queue with zero clinical content.
- House reference guards pre-installed: `coerce_int_param`, `parse_time` (offset-mandatory), reference-type guard, container guard, deep-key scan for nested denylist inputs, verified-approval (Herald signature + customer-admin channel) for the T3-class mandate verb.
- The clinician-sign simulator is **bench equipment living only in `tests/clinician_sign_simulator.py`** — it is not a tool, and the shipped engine/server/Tools contain **no signing capability in any product file**: no product file defines, imports, or references it (spec §12.1 P0-5, correction C3).

## Spec-errata flags (for spec owner; spec not edited here)

- **§6.3 vs §13.3 tension on `FULL_CHART`:** §6.3 says any `FULL_CHART` grant requires a separately counsel-reviewed mandate class and none ships in P0; §13.3's grantability test enumerates only scheduling/intake. Fix-round adjudication = the **restrictive reading (§6.3)**: `FULL_CHART` ships in NO P0 mandate and `mandate_upsert` refuses it for every purpose set with `MANDATE_TERM_NOT_GRANTABLE`.
- **Spec-gap naming — `PURPOSE_NOT_GRANTED`:** the §6.4 registry names `PURPOSE_NOT_DECLARED` only for an undeclared purpose. For a declared-but-not-granted purpose (wrong purpose for `access_pack_get`, or `AUDIT_REVIEW` outside the acting mandate's `purpose_set`), this build adds `PURPOSE_NOT_GRANTED`, following the registry's `*_NOT_GRANTED` convention (cf. `FIELD_CLASS_NOT_GRANTED`). Flagged for registry adoption at the next spec rev.

## Run

```
python3 server.py            # MCP stdio server
python3 tests/test_meridian.py   # 85 checks: DT-1..DT-5, hostile shapes, locks, BAA, tools
python3 tests/test_meridian_fix_round.py   # 45 checks: B-MER-1..5 fix-round regressions (bench shapes)
```

State: `$ECLIPSE_MERIDIAN_STATE` or `./data/state.json`. All fixtures are Synthea-shaped synthetic data; no real PHI anywhere in this tree.
