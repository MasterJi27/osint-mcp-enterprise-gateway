#!/usr/bin/env python3
# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUntypedFunctionDecorator=false, reportAssignmentType=false
"""
OSINT MCP Enterprise Gateway
Production-ready MCP server with caching, metrics, job queue, and export capabilities.
"""

import asyncio
import tempfile
import os
import sys
import shutil
import json
import ipaddress
import time
import hashlib
import re
from pathlib import Path
from datetime import datetime, timezone
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional
from mcp.server.fastmcp import FastMCP  # pyright: ignore[reportMissingImports, reportAttributeAccessIssue]


SERVER_NAME = "osint-mcp-enterprise-gateway"
SERVER_VERSION = "3.0.0"


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


DEFAULT_EXEC_TIMEOUT_SECONDS = int(os.getenv("OSINT_COMMAND_TIMEOUT_SECONDS", "300"))
REQUIRE_API_KEY = _env_flag("OSINT_REQUIRE_API_KEY", False)
EXPECTED_API_KEY = os.getenv("OSINT_API_KEY", "")
SAFE_MODE_ENABLED = _env_flag("OSINT_SAFE_MODE", False)
RATE_LIMIT_PER_MINUTE = max(1, int(os.getenv("OSINT_RATE_LIMIT_PER_MINUTE", "60")))
AUDIT_LOG_ENABLED = _env_flag("OSINT_AUDIT_LOG_ENABLED", True)
AUDIT_LOG_PATH = os.getenv("OSINT_AUDIT_LOG_PATH", "logs/audit.jsonl")
ALLOWED_TARGETS = [item.strip().lower() for item in os.getenv("OSINT_ALLOWED_TARGETS", "").split(",") if item.strip()]
DRY_RUN_MODE = _env_flag("OSINT_DRY_RUN_MODE", False)
TOOL_ALLOWLIST = [item.strip() for item in os.getenv("OSINT_TOOL_ALLOWLIST", "").split(",") if item.strip()]
TOOL_DENYLIST = [item.strip() for item in os.getenv("OSINT_TOOL_DENYLIST", "").split(",") if item.strip()]

try:
    from .cache import osint_cache
    from .models import OSINTNormalizer, OSINTResult
    from .validators import TargetValidator, target_validator, sanitize_for_output, is_safe_target
    from .metrics import (
        metrics_registry,
        tool_requests_total,
        tool_errors_total,
        tool_timeout_total,
        cache_hits_total,
        cache_misses_total,
        tool_duration_seconds,
        Timer,
    )
    from .exporters import ExporterFactory
    MODULES_AVAILABLE = True
except ImportError:
    osint_cache = None
    OSINTNormalizer = None
    OSINTResult = None
    target_validator = None
    sanitize_for_output = None
    is_safe_target = None
    tool_requests_total = None
    tool_errors_total = None
    tool_timeout_total = None
    cache_hits_total = None
    cache_misses_total = None
    tool_duration_seconds = None
    Timer = None
    ExporterFactory = None
    MODULES_AVAILABLE = False


RATE_LIMIT_LOCK = asyncio.Lock()
RATE_LIMIT_BUCKETS: Dict[str, Deque[float]] = {}

mcp = FastMCP(SERVER_NAME)


def _ok(content: Any) -> Dict[str, Any]:
    return {"success": True, "content": content}


def _error(message: str) -> Dict[str, Any]:
    return {"success": False, "error": message}


def _mask_value(value: str) -> Dict[str, Any]:
    text = value.strip()
    digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return {
        "length": len(text),
        "sha256_16": digest,
    }


def _jsonl_audit(entry: Dict[str, Any]) -> None:
    if not AUDIT_LOG_ENABLED:
        return
    try:
        path = Path(AUDIT_LOG_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except Exception:
        return


def _is_private_or_local_target(value: str) -> bool:
    probe = value.strip()
    try:
        ip = ipaddress.ip_address(probe)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        lower = probe.lower()
        return (
            lower in {"localhost", "::1"}
            or lower.endswith(".local")
            or lower.startswith("127.")
            or lower.startswith("10.")
            or lower.startswith("192.168.")
        )


def _authorize(api_key: Optional[str]) -> Optional[str]:
    if not REQUIRE_API_KEY:
        return None
    if not EXPECTED_API_KEY:
        return "OSINT_REQUIRE_API_KEY is enabled but OSINT_API_KEY is not configured."
    if not api_key:
        return "API key is required for this server."
    if api_key != EXPECTED_API_KEY:
        return "Invalid API key."
    return None


def _safe_mode_gate(value: str) -> Optional[str]:
    if not SAFE_MODE_ENABLED:
        return None
    if _is_private_or_local_target(value):
        return "Safe mode blocked private/local target."
    if ALLOWED_TARGETS and not any(token in value.lower() for token in ALLOWED_TARGETS):
        return "Safe mode blocked target outside OSINT_ALLOWED_TARGETS policy."
    return None


def _tool_gate(tool_name: str) -> Optional[str]:
    if TOOL_DENYLIST and tool_name in TOOL_DENYLIST:
        return f"Tool '{tool_name}' is denied by policy."
    if TOOL_ALLOWLIST and tool_name not in TOOL_ALLOWLIST:
        return f"Tool '{tool_name}' is not in the allowed tools list."
    return None


def _dry_run_response(tool_name: str, target: str) -> Dict[str, Any]:
    return _ok({
        "dry_run": True,
        "message": f"DRY RUN: Would execute {tool_name} on {target}",
        "tool": tool_name,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


async def _rate_limit_gate(identity: str) -> Optional[str]:
    now = time.monotonic()
    window_start = now - 60.0
    async with RATE_LIMIT_LOCK:
        bucket = RATE_LIMIT_BUCKETS.setdefault(identity, deque())
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_PER_MINUTE:
            return f"Rate limit exceeded: {RATE_LIMIT_PER_MINUTE} requests per minute."
        bucket.append(now)
    return None


async def _execute_guarded(
    *,
    tool_name: str,
    primary_input: str,
    api_key: Optional[str],
    handler: Callable[[], Any],
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    started = time.perf_counter()
    error_text = ""
    success = False

    if DRY_RUN_MODE:
        return _dry_run_response(tool_name, primary_input)

    auth_error = _authorize(api_key)
    if auth_error:
        error_text = auth_error
        result = _error(auth_error)
    else:
        tool_error = _tool_gate(tool_name)
        if tool_error:
            error_text = tool_error
            result = _error(tool_error)
        else:
            safe_error = _safe_mode_gate(primary_input)
            if safe_error:
                error_text = safe_error
                result = _error(safe_error)
            else:
                identity = api_key if api_key else "anonymous"
                rl_error = await _rate_limit_gate(identity)
                if rl_error:
                    error_text = rl_error
                    result = _error(rl_error)
                else:
                    if MODULES_AVAILABLE and tool_requests_total:
                        tool_requests_total.inc()
                    try:
                        if MODULES_AVAILABLE and tool_duration_seconds:
                            with Timer(tool_duration_seconds):
                                result = await handler()
                        else:
                            result = await handler()
                        success = bool(result.get("success", False))
                        if not success:
                            error_text = str(result.get("error", "tool failed"))
                        if MODULES_AVAILABLE and cache_misses_total and osint_cache:
                            if result.get("success"):
                                cache_misses_total.inc()
                    except asyncio.TimeoutError:
                        error_text = f"{tool_name} timed out"
                        result = _error(f"{tool_name} timed out after {DEFAULT_EXEC_TIMEOUT_SECONDS} seconds")
                        if MODULES_AVAILABLE and tool_timeout_total:
                            tool_timeout_total.inc()
                    except Exception as e:
                        error_text = str(e)
                        result = _error(f"{tool_name} execution error: {e}")
                        if MODULES_AVAILABLE and tool_errors_total:
                            tool_errors_total.inc()

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    _jsonl_audit(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool_name,
            "success": success,
            "duration_ms": duration_ms,
            "input": _mask_value(primary_input),
            "metadata": metadata or {},
            "error": error_text,
        }
    )
    return result


async def _run_triage(target: str, run_checks: bool, api_key: Optional[str]) -> Dict[str, Any]:
    kind = _detect_target_kind(target)
    recommendations: List[str] = []
    executed: Dict[str, Any] = {}

    if kind == "email":
        recommendations = ["holehe_email_search", "ghunt_google_search"]
        if run_checks:
            executed["holehe_email_search"] = await holehe_email_search(target, api_key=api_key)
            executed["ghunt_google_search"] = await ghunt_google_search(target, api_key=api_key)
    elif kind == "username":
        recommendations = ["sherlock_username_search", "maigret_username_search", "blackbird_username_search"]
        if run_checks:
            executed["sherlock_username_search"] = await sherlock_username_search(target, api_key=api_key)
            executed["maigret_username_search"] = await maigret_username_search(target, api_key=api_key)
            executed["blackbird_username_search"] = await blackbird_username_search(target, api_key=api_key)
    elif kind == "domain":
        recommendations = ["theharvester_domain_search", "spiderfoot_scan"]
        if run_checks:
            executed["theharvester_domain_search"] = await theharvester_domain_search(target, api_key=api_key)
            executed["spiderfoot_scan"] = await spiderfoot_scan(target, api_key=api_key)
    else:
        recommendations = ["holehe_email_search", "sherlock_username_search", "theharvester_domain_search"]

    return _ok(
        {
            "target": target,
            "detected_kind": kind,
            "recommended_tools": recommendations,
            "executed_checks": executed,
            "next_steps": [
                "Use the recommended tools for the detected target kind.",
                "Enable safe mode and allowed targets for controlled enterprise use.",
                "Call osint_server_health first when onboarding a new team member.",
            ],
        }
    )


async def _run_investigation_bundle(
    target: str,
    preset: str = "balanced",
    role_profile: str = "analyst",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    kind = _detect_target_kind(target)
    preset_key = preset.strip().lower()
    profile = _role_profile(role_profile)
    if preset_key == "balanced" and profile["preset"] != "balanced":
        preset_key = str(profile["preset"])

    preset_map: Dict[str, Dict[str, List[str]]] = {
        "quick": {
            "email": ["holehe_email_search"],
            "username": ["sherlock_username_search"],
            "domain": ["theharvester_domain_search"],
            "unknown": ["osint_target_triage"],
        },
        "balanced": {
            "email": ["holehe_email_search", "ghunt_google_search"],
            "username": ["sherlock_username_search", "blackbird_username_search"],
            "domain": ["theharvester_domain_search", "spiderfoot_scan"],
            "unknown": ["osint_target_triage"],
        },
        "deep": {
            "email": ["holehe_email_search", "ghunt_google_search", "osint_case_summary"],
            "username": ["sherlock_username_search", "maigret_username_search", "blackbird_username_search", "osint_case_summary"],
            "domain": ["theharvester_domain_search", "spiderfoot_scan", "osint_case_summary"],
            "unknown": ["osint_target_triage", "osint_case_summary"],
        },
    }

    chosen = preset_map.get(preset_key, preset_map["balanced"]).get(kind, preset_map["balanced"]["unknown"])

    task_map: Dict[str, Callable[[], Any]] = {
        "holehe_email_search": lambda: holehe_email_search(target, api_key=api_key),
        "ghunt_google_search": lambda: ghunt_google_search(target, api_key=api_key),
        "sherlock_username_search": lambda: sherlock_username_search(target, api_key=api_key),
        "maigret_username_search": lambda: maigret_username_search(target, api_key=api_key),
        "blackbird_username_search": lambda: blackbird_username_search(target, api_key=api_key),
        "theharvester_domain_search": lambda: theharvester_domain_search(target, api_key=api_key),
        "spiderfoot_scan": lambda: spiderfoot_scan(target, api_key=api_key),
        "osint_target_triage": lambda: osint_target_triage(target, run_checks=False, api_key=api_key),
    }

    results: Dict[str, Any] = {}
    selected_tasks = {name: task_map[name] for name in chosen if name in task_map}

    if selected_tasks:
        async def _run_named(name: str, task: Callable[[], Any]) -> None:
            results[name] = await task()

        await asyncio.gather(*[_run_named(name, task) for name, task in selected_tasks.items()])

    if "osint_case_summary" in chosen and results:
        from .models import OSINTNormalizer
        normalized_results = {}
        for tool_name, result in results.items():
            if isinstance(result, dict) and result.get("success") and result.get("content"):
                content = result["content"]
                if isinstance(content, str):
                    normalized = OSINTNormalizer.normalize_tool_output(
                        tool_name.replace("_username_search", "").replace("_email_search", "").replace("_domain_search", ""),
                        content,
                        target,
                    )
                    normalized_results[tool_name] = normalized.to_dict()
                else:
                    normalized_results[tool_name] = content
            else:
                normalized_results[tool_name] = result if isinstance(result, dict) else {"raw": result}

        results["osint_case_summary"] = osint_case_summary(
            title=f"OSINT investigation bundle: {target}",
            target=target,
            target_kind=kind,
            tool_results=normalized_results,
            analyst_notes="",
            api_key=api_key,
        )

    case_summary = _format_case_summary(
        title=f"OSINT investigation bundle: {target}",
        target=target,
        target_kind=kind,
        tool_results=results,
        analyst_notes=(
            f"Preset used: {preset_key}\n"
            f"Role profile: {role_profile.strip().lower()}\n"
            f"Summary style: {profile['summary_style']}"
        ),
    )

    return _ok(
        {
            "target": target,
            "detected_kind": kind,
            "preset": preset_key,
            "role_profile": role_profile.strip().lower(),
            "role_priority": profile["priority"],
            "selected_tools": chosen,
            "results": results,
            "case_summary": case_summary,
            "next_steps": [
                "Review the case summary and verify any high-signal hits.",
                "Use safe mode or an allowlist for enterprise-scoped investigations.",
                "Persist the markdown summary into your case management system.",
            ],
        }
    )


def _format_case_summary(
    title: str,
    target: str,
    target_kind: str,
    tool_results: Dict[str, Any],
    analyst_notes: str = "",
) -> str:
    lines = [
        f"# {title}",
        "",
        f"- Target: {target}",
        f"- Detected kind: {target_kind}",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Results",
    ]

    if not tool_results:
        lines.append("- No tool results provided.")
    else:
        for tool_name, result in tool_results.items():
            if isinstance(result, dict):
                status = "success" if result.get("success") else "failed"
                error = result.get("error")
                lines.append(f"- {tool_name}: {status}")
                if error:
                    lines.append(f"  - error: {error}")
            else:
                lines.append(f"- {tool_name}: {result}")

    if analyst_notes.strip():
        lines.extend([
            "",
            "## Analyst Notes",
            analyst_notes.strip(),
        ])

    lines.extend([
        "",
        "## Next Actions",
        "- Validate the most relevant hits manually.",
        "- Cross-check findings across at least two tools.",
        "- Save the final output to your case tracker.",
    ])
    return "\n".join(lines)


def _role_profile(profile: str) -> Dict[str, Any]:
    profiles: Dict[str, Dict[str, Any]] = {
        "analyst": {
            "preset": "balanced",
            "summary_style": "Operational summary focused on evidence quality, cross-tool correlation, and next steps.",
            "priority": "signal",
        },
        "cto": {
            "preset": "quick",
            "summary_style": "Executive summary focused on scope, risk, coverage, and decision impact.",
            "priority": "risk",
        },
        "executive": {
            "preset": "quick",
            "summary_style": "Leadership summary focused on business impact, risk, and recommended action.",
            "priority": "risk",
        },
        "red-team-lab": {
            "preset": "deep",
            "summary_style": "Lab-mode summary focused on depth, completeness, and repeatable collection.",
            "priority": "coverage",
        },
    }
    normalized = profile.strip().lower()
    return profiles.get(normalized, profiles["analyst"])


def _safe_report_name(title: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", title.strip()).strip("._-")
    if not cleaned:
        cleaned = "osint_report"
    if len(cleaned) > 200:
        cleaned = cleaned[:200]
    return cleaned


def _write_artifact(path: str, content: str) -> str:
    artifact_path = Path(path).expanduser().resolve()
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(content, encoding="utf-8")
    return str(artifact_path)


def _validate_output_format(output_format: str) -> str:
    allowed = {"txt", "csv", "xlsx"}
    value = output_format.lower().strip()
    if value not in allowed:
        raise ValueError(f"Invalid output_format '{output_format}'. Allowed values: {sorted(allowed)}")
    return value


def _detect_target_kind(value: str) -> str:
    text = value.strip()
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", text):
        return "email"
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", text):
        return "domain"
    if re.match(r"^[A-Za-z0-9_.-]{3,64}$", text):
        return "username"
    return "unknown"


def _resolve_executable(candidates: List[str]) -> Optional[str]:
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
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _resolve_script_path(env_var: str, default_path: str, description: str) -> str:
    path = os.getenv(env_var, default_path)
    if Path(path).exists():
        return path
    raise FileNotFoundError(
        f"{description} script not found at '{path}'. "
        f"Set {env_var} to the correct script path."
    )


async def run_command(command: List[str], cwd: Optional[str] = None, input_data: Optional[str] = None) -> tuple[str, str, int]:
    """Run a command in the active environment with a global execution timeout."""
    try:
        env = os.environ.copy()

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
            stdin=asyncio.subprocess.PIPE if input_data else None
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=input_data.encode() if input_data else None),
                timeout=DEFAULT_EXEC_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            try:
                process.kill()
            except OSError:
                try:
                    process.terminate()
                except OSError:
                    pass
            await process.wait()
            return "", (
                f"Command timed out after {DEFAULT_EXEC_TIMEOUT_SECONDS} seconds. "
                "Use smaller scope/target or increase OSINT_COMMAND_TIMEOUT_SECONDS."
            ), 124

        returncode = process.returncode if process.returncode is not None else 1
        return stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore'), returncode

    except FileNotFoundError as e:
        return "", f"Executable not found: {e}", 127
    except Exception as e:
        return "", str(e), 1


async def _handle_sherlock(
    username: str,
    timeout: int = 10000,
    sites: Optional[List[str]] = None,
    output_format: str = "csv",
) -> Dict[str, Any]:
    username = username.strip()
    if not username:
        raise ValueError("username cannot be empty")

    clean_output_format = _validate_output_format(output_format)
    selected_sites = [site.strip() for site in (sites or []) if site and site.strip()]

    sherlock_exe = _resolve_executable(["sherlock"])
    if not sherlock_exe:
        return _error("Sherlock executable not found in PATH.")

    cmd = [sherlock_exe, username, "--timeout", str(timeout)]

    if selected_sites:
        for site in selected_sites:
            cmd.extend(["--site", site])

    if clean_output_format == "csv":
        cmd.append("--csv")
    elif clean_output_format == "xlsx":
        cmd.append("--xlsx")

    with tempfile.TemporaryDirectory() as temp_dir:
        cmd.extend(["--folderoutput", temp_dir])

        stdout, stderr, returncode = await run_command(cmd)

        if returncode == 0:
            output_files = list(Path(temp_dir).glob(f"{username}.*"))
            results: Dict[str, Any] = {"stdout": stdout, "files": []}

            for file_path in output_files:
                try:
                    content = file_path.read_text(encoding='utf-8')
                    results["files"].append({
                        "filename": file_path.name,
                        "content": content
                    })
                except Exception as e:
                    print(f"Could not read file {file_path}: {e}", file=sys.stderr)

            return _ok(results)
        return _error(f"Sherlock failed: {stderr or stdout}")


async def _handle_holehe(email: str, only_used: bool = True, timeout: int = 10000) -> Dict[str, Any]:
    email = email.strip()
    if not email:
        raise ValueError("email cannot be empty")

    holehe_exe = _resolve_executable(["holehe"])
    if not holehe_exe:
        return _error("Holehe executable not found in PATH.")

    cmd = [holehe_exe, email, "--timeout", str(timeout)]
    if only_used:
        cmd.append("--only-used")

    stdout, stderr, returncode = await run_command(cmd)

    if returncode == 0:
        return _ok(stdout)
    return _error(f"Holehe failed: {stderr or stdout}")


async def _handle_spiderfoot(target: str) -> Dict[str, Any]:
    target = target.strip()
    if not target:
        raise ValueError("target cannot be empty")

    python_exe = sys.executable or _resolve_executable(["python", "python3"])
    if not python_exe:
        return _error("Python executable not found.")

    try:
        spiderfoot_script = _resolve_script_path(
            "SPIDERFOOT_SCRIPT_PATH",
            "/opt/spiderfoot/sf.py",
            "SpiderFoot",
        )
    except FileNotFoundError as e:
        return _error(str(e))

    cmd = [python_exe, spiderfoot_script,
           "-s", target,
           "-u", "all",
           "-o", "json",
           "-q"]

    stdout, stderr, returncode = await run_command(cmd)

    if returncode == 0:
        return _ok(stdout)
    return _error(f"SpiderFoot failed: {stderr or stdout}")


async def _handle_ghunt(identifier: str) -> Dict[str, Any]:
    identifier = identifier.strip()
    if not identifier:
        raise ValueError("identifier cannot be empty")

    ghunt_exe = _resolve_executable(["ghunt"])
    if ghunt_exe:
        cmd = [ghunt_exe, "email", identifier]
    else:
        python_exe = sys.executable or _resolve_executable(["python", "python3"])
        if not python_exe:
            return _error("Python executable not found.")

        try:
            ghunt_script = _resolve_script_path(
                "GHUNT_SCRIPT_PATH",
                "/opt/ghunt/ghunt.py",
                "GHunt",
            )
        except FileNotFoundError as e:
            return _error(str(e))

        cmd = [python_exe, ghunt_script, "email", identifier]

    stdout, stderr, returncode = await run_command(cmd)

    if returncode == 0:
        return _ok(stdout)
    return _error(f"GHunt failed: {stderr or stdout}")


async def _handle_maigret(username: str, timeout: int = 10000) -> Dict[str, Any]:
    username = username.strip()
    if not username:
        raise ValueError("username cannot be empty")

    maigret_exe = _resolve_executable(["maigret"])
    if not maigret_exe:
        return _error("Maigret executable not found in PATH.")

    cmd = [maigret_exe, username, "--timeout", str(timeout), "--json"]

    stdout, stderr, returncode = await run_command(cmd)

    if returncode == 0:
        return _ok(stdout)
    return _error(f"Maigret failed: {stderr or stdout}")


async def _handle_theharvester(domain: str, sources: str = "all", limit: int = 500) -> Dict[str, Any]:
    domain = domain.strip()
    if not domain:
        raise ValueError("domain cannot be empty")

    harvester_exe = _resolve_executable(["theHarvester", "theharvester"])
    if harvester_exe:
        cmd = [harvester_exe, "-d", domain, "-b", sources, "-l", str(limit)]
    else:
        script_path = os.getenv("THEHARVESTER_SCRIPT_PATH", "")
        if script_path and Path(script_path).exists():
            python_exe = sys.executable or _resolve_executable(["python", "python3"])
            if not python_exe:
                return _error("Python executable not found.")
            cmd = [python_exe, script_path, "-d", domain, "-b", sources, "-l", str(limit)]
        else:
            return _error(
                "theHarvester executable not found. Install it or set THEHARVESTER_SCRIPT_PATH."
            )

    stdout, stderr, returncode = await run_command(cmd)

    if returncode == 0:
        return _ok(stdout)
    return _error(f"theHarvester failed: {stderr or stdout}")


async def _handle_blackbird(username: str, timeout: int = 10000) -> Dict[str, Any]:
    username = username.strip()
    if not username:
        raise ValueError("username cannot be empty")

    python_exe = sys.executable or _resolve_executable(["python", "python3"])
    if not python_exe:
        return _error("Python executable not found.")

    try:
        blackbird_script = _resolve_script_path(
            "BLACKBIRD_SCRIPT_PATH",
            "/opt/blackbird/blackbird.py",
            "Blackbird",
        )
    except FileNotFoundError as e:
        return _error(str(e))

    cmd = [python_exe, blackbird_script, "-u", username, "--timeout", str(timeout)]

    stdout, stderr, returncode = await run_command(cmd)

    if returncode == 0:
        return _ok(stdout)
    return _error(f"Blackbird failed: {stderr or stdout}")


@mcp.tool(
    description=(
        "Search for a username across social media platforms and websites using Sherlock. "
        "Returns raw stdout plus generated output files when available."
    )
)
async def sherlock_username_search(
    username: str,
    timeout: int = 10000,
    sites: Optional[List[str]] = None,
    output_format: str = "csv",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="sherlock_username_search",
        primary_input=username,
        api_key=api_key,
        handler=lambda: _handle_sherlock(username, timeout, sites, output_format),
        metadata={"timeout": timeout, "sites_count": len(sites or []), "output_format": output_format},
    )


@mcp.tool(description="Check whether an email is registered across platforms using Holehe.")
async def holehe_email_search(
    email: str,
    only_used: bool = True,
    timeout: int = 10000,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="holehe_email_search",
        primary_input=email,
        api_key=api_key,
        handler=lambda: _handle_holehe(email, only_used, timeout),
        metadata={"timeout": timeout, "only_used": only_used},
    )


@mcp.tool(description="Run a comprehensive SpiderFoot scan for a target.")
async def spiderfoot_scan(target: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="spiderfoot_scan",
        primary_input=target,
        api_key=api_key,
        handler=lambda: _handle_spiderfoot(target),
    )


@mcp.tool(description="Search Google account information using GHunt and an email or Google ID.")
async def ghunt_google_search(identifier: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="ghunt_google_search",
        primary_input=identifier,
        api_key=api_key,
        handler=lambda: _handle_ghunt(identifier),
    )


@mcp.tool(description="Search for a username on many websites using Maigret.")
async def maigret_username_search(
    username: str,
    timeout: int = 10000,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="maigret_username_search",
        primary_input=username,
        api_key=api_key,
        handler=lambda: _handle_maigret(username, timeout),
        metadata={"timeout": timeout},
    )


@mcp.tool(description="Gather domain intelligence with theHarvester.")
async def theharvester_domain_search(
    domain: str,
    sources: str = "all",
    limit: int = 500,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="theharvester_domain_search",
        primary_input=domain,
        api_key=api_key,
        handler=lambda: _handle_theharvester(domain, sources, limit),
        metadata={"sources": sources, "limit": limit},
    )


@mcp.tool(description="Fast username OSINT search across many sites using Blackbird.")
async def blackbird_username_search(
    username: str,
    timeout: int = 10000,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="blackbird_username_search",
        primary_input=username,
        api_key=api_key,
        handler=lambda: _handle_blackbird(username, timeout),
        metadata={"timeout": timeout},
    )


@mcp.tool(description="Auto-detect a target and recommend or run the safest useful OSINT workflow.")
async def osint_target_triage(
    target: str,
    run_checks: bool = False,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="osint_target_triage",
        primary_input=target,
        api_key=api_key,
        handler=lambda: _run_triage(target, run_checks, api_key),
        metadata={"run_checks": run_checks},
    )


@mcp.tool(description="Turn one or more OSINT tool results into a practical markdown case summary.")
async def osint_case_summary(
    title: str,
    target: str,
    target_kind: str = "unknown",
    tool_results: Optional[Dict[str, Any]] = None,
    analyst_notes: str = "",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="osint_case_summary",
        primary_input=target,
        api_key=api_key,
        handler=lambda: _ok(
            {
                "title": title,
                "target": target,
                "target_kind": target_kind,
                "markdown": _format_case_summary(title, target, target_kind, tool_results or {}, analyst_notes),
                "tool_count": len(tool_results or {}),
            }
        ),
        metadata={"title": title, "target_kind": target_kind, "tool_count": len(tool_results or {})},
    )


@mcp.tool(description="Run a practical end-to-end OSINT investigation using a preset workflow and return a report-ready bundle.")
async def osint_investigation_bundle(
    target: str,
    preset: str = "balanced",
    role_profile: str = "analyst",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="osint_investigation_bundle",
        primary_input=target,
        api_key=api_key,
        handler=lambda: _run_investigation_bundle(target, preset, role_profile, api_key),
        metadata={"preset": preset, "role_profile": role_profile},
    )


@mcp.tool(description="Export a report artifact to markdown or JSON for sharing, tickets, or evidence folders.")
async def osint_export_artifact(
    title: str,
    content: Dict[str, Any],
    output_dir: str = "reports",
    format: str = "markdown",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    def _build() -> Dict[str, Any]:
        safe_name = _safe_report_name(title)
        output_path = Path(output_dir).expanduser().resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        if format.lower().strip() == "json":
            artifact_path = output_path / f"{safe_name}.json"
            written = _write_artifact(str(artifact_path), json.dumps(content, indent=2, ensure_ascii=True))
        else:
            artifact_path = output_path / f"{safe_name}.md"
            markdown = content.get("markdown")
            if not isinstance(markdown, str) or not markdown.strip():
                markdown = _format_case_summary(
                    title=title,
                    target=str(content.get("target", title)),
                    target_kind=str(content.get("target_kind", "unknown")),
                    tool_results=content.get("results", {}),
                    analyst_notes=str(content.get("analyst_notes", "")),
                )
            written = _write_artifact(str(artifact_path), markdown)

        return _ok({"path": written, "format": format.lower().strip(), "title": title})

    return await _execute_guarded(
        tool_name="osint_export_artifact",
        primary_input=title,
        api_key=api_key,
        handler=_build,
        metadata={"format": format, "output_dir": output_dir},
    )


@mcp.tool(description="Validate an OSINT target and get normalization warnings.")
async def osint_validate_target(
    target: str,
    strict: bool = False,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    return await _execute_guarded(
        tool_name="osint_validate_target",
        primary_input=target,
        api_key=api_key,
        handler=lambda: _ok(
            target_validator.to_dict() if hasattr(target_validator, "to_dict") else
            {"is_valid": True, "normalized": target.strip(), "kind": _detect_target_kind(target)}
        ) if target_validator else _ok({"normalized": target.strip(), "kind": _detect_target_kind(target)}),
        metadata={"strict": strict},
    )


@mcp.tool(description="Get cache statistics and management options.")
async def osint_cache_status(
    clear: bool = False,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    if not MODULES_AVAILABLE or not osint_cache:
        return _error("Cache module not available")

    if clear:
        count = osint_cache.clear()
        return _ok({"message": f"Cleared {count} cache entries"})

    return _ok(osint_cache.stats())


@mcp.tool(description="Get server metrics in Prometheus or JSON format.")
async def osint_metrics(
    format: str = "prometheus",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    registry = globals().get("metrics_registry")
    if not MODULES_AVAILABLE or not registry:
        return _error("Metrics module not available")

    if format.lower() == "json":
        return _ok(registry.to_json())
    return _ok({"prometheus": registry.to_prometheus()})


@mcp.tool(description="Health and policy status for enterprise operations.")
async def osint_server_health(api_key: Optional[str] = None) -> Dict[str, Any]:
    auth_error = _authorize(api_key)
    if auth_error:
        return _error(auth_error)

    required_exec = {
        "sherlock": bool(_resolve_executable(["sherlock"])),
        "holehe": bool(_resolve_executable(["holehe"])),
        "theharvester": bool(_resolve_executable(["theHarvester", "theharvester"])),
    }
    optional_exec = {
        "maigret": bool(_resolve_executable(["maigret"])),
    }
    optional_scripts = {
        "spiderfoot": Path(os.getenv("SPIDERFOOT_SCRIPT_PATH", "/opt/spiderfoot/sf.py")).exists(),
        "ghunt": Path(os.getenv("GHUNT_SCRIPT_PATH", "/opt/ghunt/ghunt.py")).exists(),
        "blackbird": Path(os.getenv("BLACKBIRD_SCRIPT_PATH", "/opt/blackbird/blackbird.py")).exists(),
    }

    health_status = {
        "server": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "policies": {
            "require_api_key": REQUIRE_API_KEY,
            "safe_mode_enabled": SAFE_MODE_ENABLED,
            "allowed_targets_count": len(ALLOWED_TARGETS),
            "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
            "audit_log_enabled": AUDIT_LOG_ENABLED,
            "audit_log_path": AUDIT_LOG_PATH,
            "dry_run_mode": DRY_RUN_MODE,
            "tool_allowlist_count": len(TOOL_ALLOWLIST),
            "tool_denylist_count": len(TOOL_DENYLIST),
        },
        "availability": {
            "required_executables": required_exec,
            "optional_executables": optional_exec,
            "optional_scripts": optional_scripts,
        },
    }

    if MODULES_AVAILABLE and osint_cache:
        health_status["cache"] = osint_cache.stats()
    if MODULES_AVAILABLE:
        registry = globals().get("metrics_registry")
        if registry:
            health_status["metrics"] = {"uptime_seconds": registry.to_json().get("uptime_seconds", 0)}

    return _ok(health_status)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
