# oord-verify

Reference verifier + CLI for Oord bundles.

## Install (editable)

```bash
python -m pip install -e ".[dev,crypto]"
````

## Verify (offline)

```bash
oord verify path/to/ood_bundle.zip
oord verify path/to/ood_bundle.zip --json
oord verify path/to/ood_bundle.zip --verbose
```

## Verify (online TL lookup)

```bash
oord verify path/to/bundle.zip --tl-url "$OORD_CORE_URL"
```
## JSON output contract

When --json is specified, oord verify always emits schema-valid JSON on stdout, even when verification fails.

* Exit code 0 → verification passed
* Exit code 1 → content / cryptographic failure
* Exit code 2 → environment / infrastructure failure

Nonzero exit codes are expected and must not be treated as CLI execution errors by callers.

Notes:

* Online checks are additive confidence only. Offline truth remains bundle-contained.
* If `cryptography` is not installed, Ed25519 verification gracefully degrades and signature checks may be reported as `null`.
