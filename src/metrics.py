#!/usr/bin/env python3
"""
Prometheus-compatible Metrics for OSINT MCP Enterprise Gateway.
Provides structured metrics for observability.
"""

import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List, Optional

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import Response


METRICS_ENABLED = os.getenv("OSINT_METRICS_ENABLED", "false").strip().lower() in {"1", "true", "yes"}
METRICS_PORT = max(8000, int(os.getenv("OSINT_METRICS_PORT", "9090")))


@dataclass
class Counter:
    name: str
    description: str
    _value: int = 0

    def inc(self, value: int = 1) -> None:
        self._value += value

    def value(self) -> int:
        return self._value

    def reset(self) -> None:
        self._value = 0


@dataclass
class Histogram:
    name: str
    description: str
    buckets: List[float] = field(default_factory=lambda: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
    _values: List[float] = field(default_factory=list)

    def observe(self, value: float) -> None:
        self._values.append(value)

    def stats(self) -> Dict[str, float]:
        if not self._values:
            return {"count": 0, "sum": 0, "min": 0, "max": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0}

        sorted_vals = sorted(self._values)
        count = len(sorted_vals)
        return {
            "count": count,
            "sum": sum(sorted_vals),
            "min": sorted_vals[0],
            "max": sorted_vals[-1],
            "avg": sum(sorted_vals) / count,
            "p50": sorted_vals[int(count * 0.5)],
            "p95": sorted_vals[int(count * 0.95)] if count > 1 else sorted_vals[0],
            "p99": sorted_vals[int(count * 0.99)] if count > 1 else sorted_vals[0],
        }

    def reset(self) -> None:
        self._values.clear()


class MetricsRegistry:
    def __init__(self):
        self._counters: Dict[str, Counter] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._gauge_values: Dict[str, float] = {}
        self._lock = Lock()
        self._started_at = time.time()

    def counter(self, name: str, description: str = "") -> Counter:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, description)
            return self._counters[name]

    def histogram(self, name: str, description: str = "", buckets: Optional[List[float]] = None) -> Histogram:
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, description, buckets or [])
            return self._histograms[name]

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauge_values[name] = value

    def get_counter(self, name: str) -> Optional[Counter]:
        return self._counters.get(name)

    def get_histogram(self, name: str) -> Optional[Histogram]:
        return self._histograms.get(name)

    def to_prometheus(self) -> str:
        lines = [
            '# OSINT MCP Enterprise Gateway Metrics',
            f'# Generated at {datetime.now(timezone.utc).isoformat()}',
            '',
            '# Counters',
        ]

        with self._lock:
            for name, counter in self._counters.items():
                lines.append(f'# {counter.description}')
                lines.append(f'{name}_total {counter.value()}')
                lines.append("")

            lines.extend(["# Histograms", ""])
            for name, hist in self._histograms.items():
                lines.append(f'# {hist.description}')
                stats = hist.stats()
                for bucket in hist.buckets:
                    count_below = sum(1 for v in hist._values if v <= bucket)
                    lines.append(f'{name}_bucket{{le="{bucket}"}} {count_below}')
                lines.append(f'{name}_bucket{{le="+Inf"}} {stats["count"]}')
                lines.append(f'{name}_sum {stats["sum"]:.6f}')
                lines.append(f'{name}_count {stats["count"]}')
                lines.append("")

            lines.extend(["# Gauges", ""])
            for name, value in self._gauge_values.items():
                lines.append(f'{name} {value}')
            lines.append("")

        return "\n".join(lines)

    def to_json(self) -> Dict[str, Any]:
        with self._lock:
            uptime = time.time() - self._started_at
            return {
                "uptime_seconds": round(uptime, 2),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "counters": {name: c.value() for name, c in self._counters.items()},
                "histograms": {
                    name: h.stats() for name, h in self._histograms.items()
                },
                "gauges": dict(self._gauge_values),
            }

    def reset_all(self) -> None:
        with self._lock:
            for counter in self._counters.values():
                counter.reset()
            for histogram in self._histograms.values():
                histogram.reset()


metrics_registry = MetricsRegistry()

tool_requests_total = metrics_registry.counter(
    "osint_tool_requests_total",
    "Total number of OSINT tool requests",
)
tool_errors_total = metrics_registry.counter(
    "osint_tool_errors_total",
    "Total number of OSINT tool errors",
)
tool_timeout_total = metrics_registry.counter(
    "osint_tool_timeouts_total",
    "Total number of OSINT tool timeouts",
)
rate_limit_hits_total = metrics_registry.counter(
    "osint_rate_limit_hits_total",
    "Total number of rate limit hits",
)
cache_hits_total = metrics_registry.counter(
    "osint_cache_hits_total",
    "Total number of cache hits",
)
cache_misses_total = metrics_registry.counter(
    "osint_cache_misses_total",
    "Total number of cache misses",
)
auth_failures_total = metrics_registry.counter(
    "osint_auth_failures_total",
    "Total number of authentication failures",
)
safe_mode_blocks_total = metrics_registry.counter(
    "osint_safe_mode_blocks_total",
    "Total number of safe mode blocks",
)

tool_duration_seconds = metrics_registry.histogram(
    "osint_tool_duration_seconds",
    "OSINT tool execution duration in seconds",
)


class Timer:
    __slots__ = ("_start", "_histogram", "_labels")

    def __init__(self, histogram: Histogram, labels: Optional[Dict[str, str]] = None):
        self._start = time.perf_counter()
        self._histogram = histogram
        self._labels = labels or {}

    def stop(self) -> float:
        elapsed = time.perf_counter() - self._start
        self._histogram.observe(elapsed)
        return elapsed

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()


async def metrics_endpoint(request) -> Response:
    metrics = request.query_params.get("format", "prometheus")

    if metrics == "json":
        return Response(
            content=json.dumps(metrics_registry.to_json(), indent=2),
            media_type="application/json",
        )

    return Response(
        content=metrics_registry.to_prometheus(),
        media_type="text/plain",
    )


def create_metrics_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/metrics", metrics_endpoint),
            Route("/health", lambda r: Response(content='{"status":"ok"}', media_type="application/json")),
        ]
    )


import json
