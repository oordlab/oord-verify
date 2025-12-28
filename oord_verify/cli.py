#oord-verify/oord_verify/cli.py
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from oord_verify.verify.verifier import verify_bundle
from oord_verify.verify.human import print_human
from oord_verify.verify.output import wrap_json

_ENV_REASON_IDS = {
    "TL_ONLINE_UNREACHABLE",
    "TL_ONLINE_UNAUTHORIZED",
    "TL_ONLINE_BAD_RESPONSE",
    "ENV_NOTARY_URL_MISSING",
}

def _is_env_failure(summary: Dict[str, Any]) -> bool:
    if summary.get("error_kind") == "env":
        return True
    rids = summary.get("reason_ids")
    if not isinstance(rids, list):
        return False
    for r in rids:
        if not isinstance(r, str):
            continue
        if r.startswith("ENV_"):
            return True
        if r in _ENV_REASON_IDS:
            return True
    return False

def _exit_code_for_results(results: List[Tuple[bool, Dict[str, Any]]]) -> int:
    any_fail = any(not ok_i for ok_i, _ in results)
    if not any_fail:
        return 0
    any_env = any(_is_env_failure(s) for ok_i, s in results if not ok_i)
    return 2 if any_env else 1

def _cmd_verify(args: argparse.Namespace) -> int:
    bundle_paths = [Path(p).expanduser().resolve() for p in args.bundles]
    results: List[Tuple[bool, Dict[str, Any]]] = []

    for path in bundle_paths:
        online_enabled = bool(args.online or args.tl_url)
        ok, summary = verify_bundle(
            path,
            tl_url=args.tl_url,
            online=online_enabled,
            tl_api_key=args.tl_api_key,
            tl_timeout_s=float(args.tl_timeout_s),
        )

        results.append((ok, summary))

    exit_code = _exit_code_for_results(results)

    if args.json:
        payload: Any
        if len(results) == 1:
            payload = wrap_json(results[0][1], exit_code)
        else:
            payload = [wrap_json(s, exit_code) for _, s in results]
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for i, (ok_i, summary_i) in enumerate(results):
            if i:
                print()
            print_human(summary_i, ok_i, verbose=bool(args.verbose))

    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oord", description="Oord verifier (verify)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_verify = subparsers.add_parser("verify", help="Verify one or more Oord bundles")
    p_verify.add_argument("bundles", nargs="+", help="Path(s) to oord_bundle_*.zip")
    p_verify.add_argument("--offline", action="store_true", help="Offline verification (default; accepted for back-compat)")
    p_verify.add_argument("--online", action="store_true", help="Enable online checks (TL fetch/consistency) when supported")
    p_verify.add_argument(
        "--tl-url",
        help="Optional Core base URL for online TL verification (e.g. http://127.0.0.1:8000)",
    )
    p_verify.add_argument(
        "--notary-url",
        dest="tl_url",
        help="Alias for --tl-url (preferred name going forward)",
    )
    p_verify.add_argument(
        "--tl-api-key",
        default=None,
        help="Optional bearer token for TL reads when not public",
    )
    p_verify.add_argument(
        "--tl-timeout-s",
        default=5.0,
        help="HTTP timeout (seconds) for online TL checks",
    )

    p_verify.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary instead of human-readable text",
    )
    p_verify.add_argument(
        "--strict",
        action="store_true",
        help="Accepted for back-compat (online env failures already produce exit code 2)",
    )
    p_verify.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed component results (hash mismatches, merkle, jwks, sig checks)",
    )
    p_verify.set_defaults(func=_cmd_verify)
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    raise SystemExit(args.func(args))

if __name__ == "__main__":
    main()
