#!/usr/bin/env python3
"""DARK-JWT-INSPECTOR - JWT decoder, analyzer and signature verifier.

Developed by DARK IBRAHIM. Offline only: tokens are never transmitted anywhere.
"""
from __future__ import annotations

import sys

if sys.version_info < (3, 8):  # checked before anything else is imported
    sys.stderr.write("DARK-JWT-INSPECTOR needs Python 3.8 or newer.\n")
    raise SystemExit(1)

import argparse
import getpass
import json
import os
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
from core import dependency_check, platform_detect
from modules import analyzer, reporter, security, verifier
from modules.decoder import JWTDecodeError, decode_token

EXIT_OK, EXIT_INPUT_ERROR, EXIT_VERIFY_PROBLEM = 0, 1, 2


# --------------------------------------------------------------------------
# Core pipeline
# --------------------------------------------------------------------------
def analyze_token(token, key=None, allowed=None, leeway=0, now=None) -> Dict[str, Any]:
    decoded = decode_token(token)
    header_info = analyzer.analyze_header(decoded.header)
    payload_info = analyzer.analyze_payload(decoded.payload)
    time_info = analyzer.analyze_time(decoded.payload, now=now, leeway=leeway)
    verification = verifier.verify_signature(decoded, key, allowed)
    findings = security.evaluate(decoded, header_info, time_info, verification)
    return {
        "decoded": decoded, "header_info": header_info, "payload_info": payload_info,
        "time_info": time_info, "verification": verification, "findings": findings,
    }


def make_report(result: Dict[str, Any]) -> Dict[str, Any]:
    return reporter.build_report(
        result["decoded"], result["header_info"], result["payload_info"],
        result["time_info"], result["verification"], result["findings"],
        platform_detect.detect_platform().to_dict(),
    )


def load_key_file(path: str) -> bytes:
    data = Path(path).expanduser().read_bytes()
    if b"-----BEGIN" not in data and data.endswith(b"\n"):
        data = data[:-2] if data.endswith(b"\r\n") else data[:-1]
    return data


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def section(title: str) -> None:
    print()
    print(config.cyan("[ %s ]" % title))
    print(config.dim("-" * 62))


def kv(label: str, value: Any) -> None:
    print("  %s %s" % (config.blue(label.ljust(18)), value))


def _pretty(obj: Any) -> str:
    return "\n".join("  " + line for line in json.dumps(obj, indent=2, ensure_ascii=False).splitlines())


def _sev(severity: str) -> str:
    if severity in ("CRITICAL", "HIGH"):
        return config.red(severity.ljust(8))
    if severity == "MEDIUM":
        return config.yellow(severity.ljust(8))
    if severity == "LOW":
        return config.cyan(severity.ljust(8))
    return config.dim(severity.ljust(8))


def print_analysis(res: Dict[str, Any]) -> None:
    d = res["decoded"]
    section("TOKEN STRUCTURE")
    kv("Segments", "3 (header.payload.signature)")
    kv("Header size", "%d chars" % len(d.header_b64))
    kv("Payload size", "%d chars" % len(d.payload_b64))
    kv("Signature", ("%d bytes" % len(d.signature)) if d.signature else config.red("EMPTY (unsigned)"))
    print(config.yellow("  NOTE: decoding only - contents are NOT trusted until the signature is verified."))

    section("HEADER")
    print(_pretty(d.header))
    alg = res["header_info"]["algorithm"]
    kv("Algorithm", alg["algorithm"])
    kv("Family", alg["family"])
    if alg.get("hash"):
        kv("Hash", alg["hash"])
    kv("Assessment", config.green("recognised") if alg["safe"] else config.red("UNSAFE / unknown"))
    kv("Note", alg["note"])
    if res["header_info"]["unusual_fields"]:
        kv("Unusual fields", ", ".join(res["header_info"]["unusual_fields"]))

    section("PAYLOAD")
    print(_pretty(d.payload))
    pi = res["payload_info"]
    kv("Claims", pi["claim_count"])
    if pi["audiences"]:
        kv("Audience", ", ".join(str(a) for a in pi["audiences"]))
    if pi["missing_registered"]:
        kv("Missing claims", ", ".join(pi["missing_registered"]))

    t = res["time_info"]
    section("TIME ANALYSIS")
    kv("Now (UTC)", t["now"])
    for name, label in (("iat", "Issued at"), ("nbf", "Not before"), ("exp", "Expires")):
        c = t[name]
        if not c["present"]:
            kv(label, config.dim("not present"))
        elif not c["valid"]:
            kv(label, config.red("invalid: %s" % c["problem"]))
        else:
            kv(label, "%s  (%s)" % (c["iso"], c["relative"]))
    colors = {"valid": config.green, "no_expiration": config.yellow, "expired": config.red,
              "not_yet_valid": config.yellow, "invalid": config.red}
    kv("State", colors[t["state"]](t["state"].upper().replace("_", " ")))
    if t["lifetime_seconds"] is not None:
        kv("Lifetime", analyzer.humanize_seconds(t["lifetime_seconds"]))

    v = res["verification"]
    section("SIGNATURE VERIFICATION")
    paint = {verifier.VERIFIED: config.green, verifier.FAILED: config.red,
             verifier.REJECTED: config.red, verifier.NOT_VERIFIED: config.yellow}[v.status]
    kv("Status", paint(v.status.upper().replace("_", " ")))
    kv("Result", v.message)
    for line in v.details:
        kv("Detail", line)

    section("SECURITY FINDINGS")
    if not res["findings"]:
        print("  " + config.green("No warnings."))
    for f in res["findings"]:
        print("  %s %s" % (_sev(f["severity"]), f["message"]))
        if f["recommendation"]:
            print("           " + config.dim("-> " + f["recommendation"]))
    print()


def print_environment() -> None:
    info = platform_detect.detect_platform()
    deps = dependency_check.check_dependencies()
    section("ENVIRONMENT")
    kv("Environment", info.environment)
    kv("OS", "%s %s" % (info.os_name, info.os_release))
    if info.distro_name:
        kv("Distribution", info.distro_name)
    kv("Architecture", "%s (%s)" % (info.architecture, info.arch_family))
    kv("Python", "%s %s" % (info.python_version, config.green("OK") if info.python_ok
                            else config.red("too old, 3.8+ needed")))
    kv("Package manager", info.package_manager)
    for note in info.notes:
        kv("Note", note)
    section("DEPENDENCIES / FEATURES")
    for d in deps:
        kv(d.name, "%s %s" % (config.green("available") if d.available else config.yellow("missing"),
                              d.version))
        print("  " + " " * 18 + " " + config.dim(d.note))
    for name, st in dependency_check.feature_matrix(deps).items():
        kv(name, config.green("available") if st["available"]
           else config.yellow("unavailable - " + st["note"]))
    section("INSTALL HINTS FOR THIS ENVIRONMENT")
    for line in platform_detect.install_hints(info):
        print("  " + line)
    print()


def print_about() -> None:
    print(config.cyan("%s v%s" % (config.APP_NAME, config.VERSION)))
    print(config.green(config.identity_block()))
    print("\n  Decodes, analyses and verifies JWTs fully offline.")
    print("  No secret guessing, no brute force, no network access.\n")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number")
    if number < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return number


def build_parser() -> argparse.ArgumentParser:
    epilog = (
        "Developer identity\n" + config.identity_block() + "\n\n"
        "Examples:\n"
        "  python main.py <token>                      decode + analyse (offline)\n"
        "  python main.py --token-file t.txt --secret-env JWT_SECRET --alg HS256\n"
        "  python main.py - < t.txt --key-file public.pem --alg RS256\n"
        "  python main.py <token> --output reports/r.json\n"
        "  python main.py -i                           interactive mode\n"
    )
    p = argparse.ArgumentParser(
        prog="main.py",
        description="%s v%s - JWT decoder, analyzer and signature verifier.\n"
                    "Developed by %s - %s" % (config.APP_NAME, config.VERSION, config.DEVELOPER, config.TITLE),
        epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("token", nargs="?", help="JWT string, or '-' to read it from stdin")
    p.add_argument("--token-file", metavar="FILE", help="read the token from a file")
    p.add_argument("-k", "--key-file", metavar="FILE",
                   help="HMAC secret file, or PEM public key/certificate (RS/PS/ES)")
    p.add_argument("--secret-env", metavar="VAR", help="read the HMAC secret from an environment variable")
    p.add_argument("--prompt-secret", action="store_true", help="type the HMAC secret (hidden input)")
    p.add_argument("--alg", action="append", metavar="ALG",
                   help="expected algorithm(s); token with another alg is rejected (repeatable)")
    p.add_argument("--leeway", type=_non_negative_int, default=0, metavar="SEC", help="clock-skew tolerance in seconds")
    p.add_argument("-o", "--output", metavar="FILE", help="save a redacted JSON report (your consent to write)")
    p.add_argument("--json", action="store_true", help="print the redacted JSON report to stdout")
    p.add_argument("-i", "--interactive", action="store_true", help="interactive menu")
    p.add_argument("--check-env", action="store_true", help="show platform and dependency status")
    p.add_argument("--selftest", action="store_true", help="run the bundled automated tests")
    p.add_argument("--about", action="store_true", help="show developer information")
    p.add_argument("--no-color", action="store_true", help="disable colours")
    p.add_argument("--no-banner", action="store_true", help="hide the startup banner")
    p.add_argument("--version", action="store_true", help="show version")
    return p


def resolve_key(args) -> Optional[bytes]:
    if args.key_file:
        return load_key_file(args.key_file)
    if args.secret_env:
        value = os.environ.get(args.secret_env)
        if value is None:
            raise ValueError("environment variable %s is not set" % args.secret_env)
        return value.encode("utf-8")
    if args.prompt_secret:
        return getpass.getpass("HMAC secret (hidden): ").encode("utf-8")
    return None


def read_token(args) -> Optional[str]:
    if args.token_file:
        return Path(args.token_file).expanduser().read_text(encoding="utf-8").strip()
    if args.token == "-":
        return sys.stdin.read().strip()
    return args.token


def run_selftest() -> int:
    suite = unittest.defaultTestLoader.discover(str(config.BASE_DIR / "tests"),
                                                top_level_dir=str(config.BASE_DIR))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return EXIT_OK if result.wasSuccessful() else EXIT_VERIFY_PROBLEM


def run_cli(args) -> int:
    try:
        token = read_token(args)
        key = resolve_key(args)
    except (OSError, ValueError) as exc:
        print(config.red("[!] %s" % exc), file=sys.stderr)
        return EXIT_INPUT_ERROR
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return EXIT_INPUT_ERROR
    allowed: List[str] = []
    for item in args.alg or []:
        allowed.extend(a.strip() for a in item.split(",") if a.strip())
    try:
        res = analyze_token(token, key, allowed or None, args.leeway)
    except JWTDecodeError as exc:
        print(config.red("[!] Invalid token: %s" % exc), file=sys.stderr)
        return EXIT_INPUT_ERROR

    report = make_report(res)
    if args.json:
        print(reporter.to_json(report))
    else:
        print_analysis(res)
    if args.output:
        path = reporter.save_report(report, args.output, consent=True)
        print(config.green("[+] Redacted report saved to %s" % path), file=sys.stderr)

    status = res["verification"].status
    if key is not None and status != verifier.VERIFIED:
        return EXIT_VERIFY_PROBLEM
    if status == verifier.REJECTED:
        return EXIT_VERIFY_PROBLEM
    return EXIT_OK


# --------------------------------------------------------------------------
# Interactive mode
# --------------------------------------------------------------------------
MENU = """
  1) Enter / change token
  2) Decode and analyse (offline, no key)
  3) Verify signature (secret or PEM key file)
  4) Show security warnings only
  5) Export redacted JSON report (asks permission)
  6) Environment check
  7) About
  0) Exit
"""


def interactive() -> int:
    token: Optional[str] = None
    last: Optional[Dict[str, Any]] = None
    while True:
        print(config.cyan(MENU))
        try:
            choice = input(config.green("dark-jwt> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return EXIT_OK
        try:
            if choice == "0":
                return EXIT_OK
            if choice == "1":
                candidate = input("Paste token: ").strip()
                token, last = None, None
                decode_token(candidate)  # raises JWTDecodeError for malformed input
                token = candidate
                print(config.green("[+] Token accepted (kept in memory only)."))
            elif choice in ("2", "3", "4", "5", "6", "7"):
                if choice == "6":
                    print_environment()
                    continue
                if choice == "7":
                    print_about()
                    continue
                if not token:
                    print(config.yellow("[!] Enter a token first (option 1)."))
                    continue
                if choice == "3":
                    kind = input("Key type - [s]ecret (hidden) or [f]ile path: ").strip().lower()
                    key = (getpass.getpass("Secret: ").encode("utf-8") if kind.startswith("s")
                           else load_key_file(input("Key file path: ").strip()))
                    alg = input("Expected algorithm (blank = any supported): ").strip()
                    last = analyze_token(token, key, [alg] if alg else None)
                    print_analysis(last)
                elif choice in ("2", "4"):
                    last = analyze_token(token)
                    if choice == "2":
                        print_analysis(last)
                    else:
                        section("SECURITY FINDINGS")
                        for f in last["findings"]:
                            print("  %s %s" % (_sev(f["severity"]), f["message"]))
                elif choice == "5":
                    last = last or analyze_token(token)
                    default = reporter.default_report_path(make_report(last))
                    answer = input("Save a redacted report to %s ? [y/N] " % default).strip().lower()
                    if answer == "y":
                        saved = reporter.save_report(make_report(last), default, consent=True)
                        print(config.green("[+] Saved: %s" % saved))
                    else:
                        print("Nothing was saved.")
            else:
                print(config.yellow("[!] Unknown option."))
        except JWTDecodeError as exc:
            print(config.red("[!] Invalid token: %s" % exc))
        except (OSError, ValueError) as exc:
            print(config.red("[!] %s" % exc))
        except (EOFError, KeyboardInterrupt):
            print()
            return EXIT_OK


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config.use_color(False if args.no_color else None)

    if args.version:
        print("%s v%s - Developed by %s" % (config.APP_NAME, config.VERSION, config.DEVELOPER))
        return EXIT_OK
    if args.selftest:
        return run_selftest()
    quiet = args.json or args.no_banner
    if not quiet:
        print(config.banner())
    if args.about:
        print_about()
        return EXIT_OK
    if args.check_env:
        print_environment()
        return EXIT_OK
    no_token = not (args.token or args.token_file)
    if args.interactive or (no_token and sys.stdin.isatty()):
        return interactive()
    if no_token:
        parser.print_help()
        return EXIT_INPUT_ERROR
    return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
