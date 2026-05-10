#!/usr/bin/env python3
"""
Simple HTTP Dashboard for OSINT MCP Enterprise Gateway.
Provides health checks, metrics, and job status views.
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, Response
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles

from .cache import osint_cache
from .jobs import job_queue
from .metrics import metrics_registry, METRICS_PORT


DASHBOARD_ENABLED = os.getenv("OSINT_DASHBOARD_ENABLED", "false").strip().lower() in {"1", "true", "yes"}
DASHBOARD_PORT = max(8000, int(os.getenv("OSINT_DASHBOARD_PORT", "9091")))
DASHBOARD_SECRET = os.getenv("OSINT_DASHBOARD_SECRET", "")


STYLES = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f1a; color: #e0e0e0; padding: 20px; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { color: #00ff88; font-size: 2em; margin-bottom: 20px; }
h2 { color: #00ccff; margin: 20px 0 10px; }
.card { background: #1a1a2e; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #2a2a4e; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
.stat { font-size: 2em; color: #00ff88; }
.stat-label { color: #888; font-size: 0.8em; }
.tool-status { display: flex; align-items: center; padding: 10px; border-bottom: 1px solid #2a2a4e; }
.tool-status:last-child { border-bottom: none; }
.status-dot { width: 10px; height: 10px; border-radius: 50%; margin-right: 10px; }
.status-dot.green { background: #00ff88; }
.status-dot.yellow { background: #ffcc00; }
.status-dot.red { background: #ff4444; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 12px; border-bottom: 1px solid #2a2a4e; }
th { color: #00ccff; }
tr:hover { background: #2a2a4e; }
.badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
.badge.green { background: #00ff8833; color: #00ff88; }
.badge.yellow { background: #ffcc0033; color: #ffcc00; }
.badge.red { background: #ff444433; color: #ff4444; }
.badge.blue { background: #00ccff33; color: #00ccff; }
nav { margin-bottom: 20px; }
nav a { color: #00ccff; margin-right: 20px; text-decoration: none; }
nav a:hover { color: #00ff88; }
pre { background: #0a0a1a; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 0.9em; }
"""


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>OSINT MCP Enterprise Gateway</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>{styles}</style>
</head>
<body>
    <div class="container">
        <h1>OSINT MCP Enterprise Gateway</h1>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/tools">Tools</a>
            <a href="/jobs">Jobs</a>
            <a href="/metrics">Metrics</a>
            <a href="/cache">Cache</a>
        </nav>

        <div class="grid">
            <div class="card">
                <div class="stat">{uptime}</div>
                <div class="stat-label">Uptime</div>
            </div>
            <div class="card">
                <div class="stat">{total_requests}</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="card">
                <div class="stat">{cache_hit_rate}%</div>
                <div class="stat-label">Cache Hit Rate</div>
            </div>
            <div class="card">
                <div class="stat">{active_jobs}</div>
                <div class="stat-label">Active Jobs</div>
            </div>
        </div>

        {content}
    </div>
</body>
</html>
"""


async def dashboard_home(request) -> Response:
    uptime_seconds = metrics_registry.to_json().get("uptime_seconds", 0)
    uptime = _format_duration(uptime_seconds)

    total_requests = metrics_registry.get_counter("osint_tool_requests_total")
    total_requests = total_requests.value() if total_requests else 0

    cache_stats = osint_cache.stats()
    cache_hit_rate = cache_stats.get("hit_rate_percent", 0)

    jobs_stats = await job_queue.stats()
    active_jobs = jobs_stats.get("total_jobs", 0)

    content = """
    <div class="card">
        <h2>System Status</h2>
        <table>
            <tr><td>Server Status</td><td><span class="badge green">Running</span></td></tr>
            <tr><td>Cache Enabled</td><td><span class="badge {cache_badge}">{cache_status}</span></td></tr>
            <tr><td>Metrics Enabled</td><td><span class="badge {metrics_badge}">{metrics_status}</span></td></tr>
            <tr><td>Python Version</td><td>{python_version}</td></tr>
        </table>
    </div>
    """.format(
        cache_badge="green" if cache_stats.get("enabled") else "yellow",
        cache_status="Enabled" if cache_stats.get("enabled") else "Disabled",
        metrics_badge="green" if metrics_registry.to_json().get("uptime_seconds", 0) > 0 else "yellow",
        metrics_status="Enabled" if metrics_registry.to_json().get("uptime_seconds", 0) > 0 else "Disabled",
        python_version=__import__("sys").version.split()[0],
    )

    html = HTML_TEMPLATE.format(
        styles=STYLES,
        uptime=uptime,
        total_requests=total_requests,
        cache_hit_rate=round(cache_hit_rate, 1),
        active_jobs=active_jobs,
        content=content,
    )

    return HTMLResponse(content=html)


async def tools_page(request) -> Response:
    from .osint_tools_mcp_server import _resolve_executable

    tools_status = [
        {"name": "Sherlock", "status": bool(_resolve_executable(["sherlock"]))},
        {"name": "Holehe", "status": bool(_resolve_executable(["holehe"]))},
        {"name": "Maigret", "status": bool(_resolve_executable(["maigret"]))},
        {"name": "theHarvester", "status": bool(_resolve_executable(["theHarvester", "theharvester"]))},
    ]

    rows = ""
    for tool in tools_status:
        status_class = "green" if tool["status"] else "red"
        rows += f"""
        <tr>
            <td>{tool['name']}</td>
            <td><span class="badge {status_class}">{'Available' if tool['status'] else 'Not Found'}</span></td>
        </tr>
        """

    content = f"""
    <div class="card">
        <h2>Tool Availability</h2>
        <table>
            <tr><th>Tool</th><th>Status</th></tr>
            {rows}
        </table>
    </div>
    """

    html = HTML_TEMPLATE.format(
        styles=STYLES,
        uptime="-",
        total_requests="-",
        cache_hit_rate="-",
        active_jobs="-",
        content=content,
    )

    return HTMLResponse(content=html)


async def jobs_page(request) -> Response:
    jobs = await job_queue.list_jobs(limit=50)
    rows = ""

    for job in jobs:
        status_class = {
            "pending": "yellow",
            "running": "blue",
            "completed": "green",
            "failed": "red",
            "cancelled": "red",
            "timeout": "yellow",
        }.get(job.status, "yellow")

        created = job.created_at[:19] if job.created_at else "-"

        rows += f"""
        <tr>
            <td><code>{job.id[:8]}...</code></td>
            <td>{job.tool_name}</td>
            <td>{job.target[:30]}</td>
            <td><span class="badge {status_class}">{job.status}</span></td>
            <td>{created}</td>
        </tr>
        """

    content = f"""
    <div class="card">
        <h2>Job Queue ({len(jobs)} jobs)</h2>
        <table>
            <tr><th>ID</th><th>Tool</th><th>Target</th><th>Status</th><th>Created</th></tr>
            {rows or '<tr><td colspan="5">No jobs</td></tr>'}
        </table>
    </div>
    """

    html = HTML_TEMPLATE.format(
        styles=STYLES,
        uptime="-",
        total_requests="-",
        cache_hit_rate="-",
        active_jobs=len(jobs),
        content=content,
    )

    return HTMLResponse(content=html)


async def metrics_page(request) -> Response:
    metrics_json = metrics_registry.to_json()
    content = f"""
    <div class="card">
        <h2>Prometheus Metrics</h2>
        <pre>{metrics_registry.to_prometheus()}</pre>
    </div>
    <div class="card">
        <h2>Metrics JSON</h2>
        <pre>{json.dumps(metrics_json, indent=2)}</pre>
    </div>
    """

    html = HTML_TEMPLATE.format(
        styles=STYLES,
        uptime=_format_duration(metrics_json.get("uptime_seconds", 0)),
        total_requests=metrics_json.get("counters", {}).get("osint_tool_requests_total", 0),
        cache_hit_rate="-",
        active_jobs="-",
        content=content,
    )

    return HTMLResponse(content=html)


async def cache_page(request) -> Response:
    cache_stats = osint_cache.stats()
    content = f"""
    <div class="card">
        <h2>Cache Statistics</h2>
        <table>
            <tr><td>Enabled</td><td><span class="badge {"green" if cache_stats.get("enabled") else "yellow"}">{cache_stats.get("enabled")}</span></td></tr>
            <tr><td>TTL (seconds)</td><td>{cache_stats.get("ttl_seconds")}</td></tr>
            <tr><td>Cache Directory</td><td>{cache_stats.get("cache_dir")}</td></tr>
            <tr><td>Hits</td><td>{cache_stats.get("hits")}</td></tr>
            <tr><td>Misses</td><td>{cache_stats.get("misses")}</td></tr>
            <tr><td>Hit Rate</td><td>{cache_stats.get("hit_rate_percent")}%</td></tr>
            <tr><td>Evictions</td><td>{cache_stats.get("evictions")}</td></tr>
            <tr><td>Cached Entries</td><td>{cache_stats.get("cached_entries")}</td></tr>
        </table>
    </div>
    """

    html = HTML_TEMPLATE.format(
        styles=STYLES,
        uptime="-",
        total_requests="-",
        cache_hit_rate=round(cache_stats.get("hit_rate_percent", 0), 1),
        active_jobs="-",
        content=content,
    )

    return HTMLResponse(content=html)


async def health_endpoint(request) -> Response:
    from .osint_tools_mcp_server import _resolve_executable

    cache_stats = osint_cache.stats()
    jobs_stats = await job_queue.stats()

    return JSONResponse({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": {
            "sherlock": bool(_resolve_executable(["sherlock"])),
            "holehe": bool(_resolve_executable(["holehe"])),
        },
        "cache": {
            "enabled": cache_stats.get("enabled", False),
            "hit_rate_percent": cache_stats.get("hit_rate_percent", 0),
        },
        "jobs": {
            "total": jobs_stats.get("total_jobs", 0),
            "active_workers": jobs_stats.get("active_workers", 0),
        },
        "metrics": {
            "uptime_seconds": metrics_registry.to_json().get("uptime_seconds", 0),
        },
    })


async def prometheus_metrics(request) -> Response:
    return Response(
        content=metrics_registry.to_prometheus(),
        media_type="text/plain",
    )


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"


def create_dashboard_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/", dashboard_home),
            Route("/tools", tools_page),
            Route("/jobs", jobs_page),
            Route("/metrics", metrics_page),
            Route("/cache", cache_page),
            Route("/health", health_endpoint),
            Route("/prometheus", prometheus_metrics),
        ],
    )


async def run_dashboard():
    if not DASHBOARD_ENABLED:
        return

    try:
        import uvicorn
    except ImportError:
        return

    app = create_dashboard_app()
    config = uvicorn.Config(app, host="0.0.0.0", port=DASHBOARD_PORT, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

