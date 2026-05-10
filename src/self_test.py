#!/usr/bin/env python3
"""Preflight diagnostics for OSINT MCP Enterprise Gateway."""

import argparse
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Tuple

REQUIRED_EXECUTABLES = {
    "sherlock": ["sherlock"],
    "holehe": ["holehe"],
    "theharvester": ["theHarvester", "theharvester"],
}

OPTIONAL_EXECUTABLES = {
    "maigret": ["maigret"],
}

OPTIONAL_SCRIPTS = {
    "spiderfoot": {
        "env": "SPIDERFOOT_SCRIPT_PATH",
        "default": "/opt/spiderfoot/sf.py",
    },
    "ghunt": {
        "env": "GHUNT_SCRIPT_PATH",
        "default": "/opt/ghunt/ghunt.py",
    },
    "blackbird": {
        "env": "BLACKBIRD_SCRIPT_PATH",
        "default": "/opt/blackbird/blackbird.py",
    },
}

REQUIRED_PYTHON_PACKAGES = ["mcp"]

PRODUCTION_PYTHON_PACKAGES = [
    "starlette",
    "uvicorn",
]


def resolve_executable(candidates: List[str]) -> str:
    scripts_dir = Path(sys.executable).resolve().parent if sys.executable else None
    for candidate in candidates:
        if scripts_dir:
            direct = scripts_dir / candidate
            if direct.exists():
                return str(direct)
            if os.name == "nt":
                direct_exe = scripts_dir / f"{candidate}.exe"
                if direct_exe.exists():
                    return str(direct_exe)
        found = shutil.which(candidate)
        if found:
            return found
    return ""


def package_installed(package_name: str) -> bool:
    return importlib.util.find_spec(package_name) is not None


def check_scripts() -> Tuple[Dict[str, str], Dict[str, str]]:
    found: Dict[str, str] = {}
    missing: Dict[str, str] = {}

    for key, cfg in OPTIONAL_SCRIPTS.items():
        value = os.getenv(cfg["env"], cfg["default"])
        if Path(value).exists():
            found[key] = value
        else:
            missing[key] = (
                f"Missing script path: {value}. "
                f"Set {cfg['env']} to your local script location."
            )

    return found, missing


def check_production_modules() -> Tuple[Dict[str, bool], Dict[str, bool]]:
    available: Dict[str, bool] = {}
    missing: Dict[str, bool] = {}

    for pkg in PRODUCTION_PYTHON_PACKAGES:
        installed = package_installed(pkg)
        available[pkg] = installed
        if not installed:
            missing[pkg] = True

    return available, missing


def main() -> int:
    parser = argparse.ArgumentParser(description="Run preflight checks for OSINT MCP Enterprise Gateway")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print diagnostics as JSON",
    )
    parser.add_argument(
        "--strict-optional",
        action="store_true",
        help="Fail if optional script-based tools are missing",
    )
    args = parser.parse_args()

    python_ok = sys.version_info >= (3, 10)
    python_recommended = sys.version_info < (3, 14)
    package_status = {pkg: package_installed(pkg) for pkg in REQUIRED_PYTHON_PACKAGES}

    exe_found: Dict[str, str] = {}
    exe_missing: Dict[str, str] = {}
    for tool, candidates in REQUIRED_EXECUTABLES.items():
        resolved = resolve_executable(candidates)
        if resolved:
            exe_found[tool] = resolved
        else:
            exe_missing[tool] = f"Executable not found in PATH. Tried: {', '.join(candidates)}"

    optional_exe_found: Dict[str, str] = {}
    optional_exe_missing: Dict[str, str] = {}
    for tool, candidates in OPTIONAL_EXECUTABLES.items():
        resolved = resolve_executable(candidates)
        if resolved:
            optional_exe_found[tool] = resolved
        else:
            optional_exe_missing[tool] = f"Optional executable not found in PATH. Tried: {', '.join(candidates)}"

    scripts_found, scripts_missing = check_scripts()
    production_available, production_missing = check_production_modules()

    ok = python_ok and all(package_status.values()) and not exe_missing
    if args.strict_optional and scripts_missing:
        ok = False

    report = {
        "status": "ok" if ok else "failed",
        "python": {
            "required": ">=3.10",
            "recommended": "3.10 - 3.13",
            "current": sys.version.split()[0],
            "ok": python_ok,
            "recommended_ok": python_recommended,
        },
        "packages": package_status,
        "production_modules": production_available,
        "required_executables": {
            "found": exe_found,
            "missing": exe_missing,
        },
        "optional_executables": {
            "found": optional_exe_found,
            "missing": optional_exe_missing,
        },
        "optional_scripts": {
            "found": scripts_found,
            "missing": scripts_missing,
        },
        "environment_variables": {
            "OSINT_SAFE_MODE": os.getenv("OSINT_SAFE_MODE", "false"),
            "OSINT_REQUIRE_API_KEY": os.getenv("OSINT_REQUIRE_API_KEY", "false"),
            "OSINT_RATE_LIMIT_PER_MINUTE": os.getenv("OSINT_RATE_LIMIT_PER_MINUTE", "60"),
            "OSINT_CACHE_ENABLED": os.getenv("OSINT_CACHE_ENABLED", "true"),
            "OSINT_METRICS_ENABLED": os.getenv("OSINT_METRICS_ENABLED", "false"),
            "OSINT_DRY_RUN_MODE": os.getenv("OSINT_DRY_RUN_MODE", "false"),
        },
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("OSINT MCP Enterprise Gateway Preflight")
        print(f"- Status: {report['status']}")
        print(f"- Python: {report['python']['current']} (ok={report['python']['ok']})")
        print(f"- Python recommended range ok: {report['python']['recommended_ok']} ({report['python']['recommended']})")

        for pkg, installed in package_status.items():
            print(f"- Package {pkg}: {'ok' if installed else 'missing'}")

        print("\nProduction Modules:")
        for pkg, available in production_available.items():
            print(f"  - {pkg}: {'available' if available else 'missing'}")

        if exe_found:
            print("\nRequired executables found:")
            for name, path in exe_found.items():
                print(f"  - {name}: {path}")

        if exe_missing:
            print("\nRequired executables missing:")
            for name, reason in exe_missing.items():
                print(f"  - {name}: {reason}")

        if optional_exe_found:
            print("\nOptional executables found:")
            for name, path in optional_exe_found.items():
                print(f"  - {name}: {path}")

        if optional_exe_missing:
            print("\nOptional executables missing:")
            for name, reason in optional_exe_missing.items():
                print(f"  - {name}: {reason}")

        if scripts_found:
            print("\nOptional scripts found:")
            for name, path in scripts_found.items():
                print(f"  - {name}: {path}")

        if scripts_missing:
            print("\nOptional scripts missing:")
            for name, reason in scripts_missing.items():
                print(f"  - {name}: {reason}")

        print("\nEnvironment Variables:")
        for key, value in report["environment_variables"].items():
            print(f"  - {key}: {value}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
