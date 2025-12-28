# oord-verify

Reference verifier + CLI for **Oord protocol v1** bundles.

This tool verifies the integrity, authenticity, and (optionally) transparency-log consistency of Oord bundles.
It is designed to be **independent, reproducible, and fully offline by default**.

---

## Protocol compatibility

**Supports:** `oord-protocol` **v1.0.2**

Verifier releases are explicitly pinned to protocol versions.
See CI configuration for enforced contract checks.

---

## Install (editable)

```bash
python -m pip install -e ".[dev,crypto]"

```

## Verify (offline — default)

Offline verification checks bundle-contained truth only.
No network access is performed.

```bash
oord verify path/to/oord_bundle.zip
oord verify path/to/oord_bundle.zip --json
oord verify path/to/oord_bundle.zip --verbose

```

Offline verification includes:

* ZIP safety and layout checks
* Manifest schema validation
* File hash verification
* Merkle root recomputation
* Manifest signature verification (Ed25519, via JWKS snapshot)
* Transparency Log proof verification if included in the bundle

## Verify (online TL consistency check)

Online mode adds consistency checks only against a Notary / TL service.

```bash
oord verify path/to/oord_bundle.zip --tl-url "$OORD_CORE_URL"

```

**Semantics:**

* Offline verification always runs first
* Online checks never redefine truth
* Network / infra failures are classified as environment errors (exit code 2)
* Cryptographic contradictions are classified as verification failures (exit code 1)

## JSON output contract

When `--json` is specified, `oord verify` always emits schema-valid JSON on stdout, even when verification fails.

**Exit codes:**

* **0** → verification passed
* **1** → content / cryptographic failure
* **2** → environment / infrastructure failure

Non-zero exit codes are expected and must not be treated as CLI execution errors by callers.

The JSON output validates against:
`schemas/verify_output_v1.json`

## Notes

* Online checks provide additive confidence only; offline truth remains bundle-contained
* If cryptography is not installed, Ed25519 verification degrades gracefully and signature checks may be reported as null
* This tool intentionally does not embed protocol semantics; protocol truth lives in `oord-protocol`

---

## Should you add more docs? Yes — but only two, and very short.

You’re at the stage where **small, sharp docs beat big ones**.

### 1️⃣ Add this to **`oord-verify`**

**File:** `docs/STATE.md` (or `docs/COMPATIBILITY.md`)

Purpose: make the contract explicit for future you and contributors.

```md
# oord-verify — State and Compatibility

This verifier implements the Oord Protocol contract as defined in:

- `oord-protocol` v1.0.2

## Guarantees

- Offline verification is fully self-contained
- Online checks are additive and never redefine truth
- Exit codes and reason IDs are stable within a protocol version
- CI enforces compatibility against the pinned protocol version

## Non-goals

- Owning protocol truth
- Owning Notary operations
- Interpreting or mutating bundle contents

```