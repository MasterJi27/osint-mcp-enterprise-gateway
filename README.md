# OSINT MCP Enterprise Gateway

Production-ready MCP server that exposes OSINT tools to MCP clients over stdio with enterprise-grade features.

> **Note:** This project is built for legitimate and authorized OSINT workflows. It is not designed for harmful use.

## What This Project Is

This server wraps the following tools behind MCP with production features:

- **Sherlock** - Username search across social media
- **Holehe** - Email account detection
- **SpiderFoot** - Comprehensive domain scanning
- **GHunt** - Google account investigation
- **Maigret** - Advanced username enumeration
- **theHarvester** - Domain intelligence gathering
- **Blackbird** - Fast username OSINT

## Production Features

### Core Infrastructure
- **Result Caching** - SHA256-based deduplication with TTL expiration
- **Output Normalization** - Common schema for all tool outputs
- **Input Validation** - Comprehensive target validation and sanitization

### Enterprise Controls
- **API Key Authentication** - Secure tool access
- **Rate Limiting** - Per-identity abuse protection
- **Safe Mode** - Block private/local targets
- **Tool Allowlist/Denylist** - Granular tool access control
- **Dry Run Mode** - Test without execution
- **Comprehensive Audit Logging** - JSONL audit trail

### Observability
- **Prometheus Metrics** - Request latency, success/failure rates
- **Health Endpoint** - Runtime readiness checks
- **Cache Statistics** - Hit rate and eviction tracking

### Output & Export
- **Markdown Export** - Report-ready summaries
- **JSON Export** - Structured data sharing
- **CSV Export** - Spreadsheet analysis
- **PDF Export** - Branded reports

### Async & Dashboard
- **Job Queue** - Background processing for long scans
- **HTTP Dashboard** - Status page and metrics

## Quick Start

### Windows
```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup_windows.ps1
python src/osint_tools_mcp_server.py
```

### Linux/macOS
```bash
bash scripts/setup_unix.sh
python src/osint_tools_mcp_server.py
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `sherlock_username_search` | Search username across platforms |
| `holehe_email_search` | Check email registration |
| `maigret_username_search` | Advanced username enumeration |
| `theharvester_domain_search` | Domain intelligence |
| `spiderfoot_scan` | Comprehensive domain scan |
| `ghunt_google_search` | Google account investigation |
| `blackbird_username_search` | Fast username OSINT |
| `osint_target_triage` | Auto-detect target type |
| `osint_case_summary` | Generate markdown report |
| `osint_investigation_bundle` | Run preset workflows |
| `osint_export_artifact` | Export to multiple formats |
| `osint_validate_target` | Validate and normalize targets |
| `osint_cache_status` | Cache management |
| `osint_metrics` | Prometheus metrics |
| `osint_server_health` | Health and policy status |

## Environment Variables

### Core
| Variable | Default | Description |
|----------|---------|-------------|
| `OSINT_COMMAND_TIMEOUT_SECONDS` | 300 | Command timeout |
| `OSINT_REQUIRE_API_KEY` | false | Require API key auth |
| `OSINT_API_KEY` | - | API key value |
| `OSINT_RATE_LIMIT_PER_MINUTE` | 60 | Rate limit |
| `OSINT_SAFE_MODE` | false | Block private targets |
| `OSINT_ALLOWED_TARGETS` | - | Comma-separated allowlist |
| `OSINT_AUDIT_LOG_ENABLED` | true | Enable audit logging |
| `OSINT_AUDIT_LOG_PATH` | logs/audit.jsonl | Audit log path |
| `OSINT_DRY_RUN_MODE` | false | Test mode (no execution) |
| `OSINT_TOOL_ALLOWLIST` | - | Allowed tools only |
| `OSINT_TOOL_DENYLIST` | - | Blocked tools |

### Production Features
| Variable | Default | Description |
|----------|---------|-------------|
| `OSINT_CACHE_ENABLED` | true | Enable result caching |
| `OSINT_CACHE_TTL_SECONDS` | 3600 | Cache TTL |
| `OSINT_CACHE_DIR` | cache/ | Cache directory |
| `OSINT_METRICS_ENABLED` | false | Enable metrics endpoint |
| `OSINT_METRICS_PORT` | 9090 | Metrics port |
| `OSINT_DASHBOARD_ENABLED` | false | Enable dashboard |
| `OSINT_DASHBOARD_PORT` | 9091 | Dashboard port |
| `OSINT_JOB_TIMEOUT_SECONDS` | 3600 | Job timeout |
| `OSINT_JOB_RETENTION_HOURS` | 168 | Job retention |

### Script Paths
| Variable | Default | Description |
|----------|---------|-------------|
| `SPIDERFOOT_SCRIPT_PATH` | /opt/spiderfoot/sf.py | SpiderFoot path |
| `GHUNT_SCRIPT_PATH` | /opt/ghunt/ghunt.py | GHunt path |
| `BLACKBIRD_SCRIPT_PATH` | /opt/blackbird/blackbird.py | Blackbird path |
| `THEHARVESTER_SCRIPT_PATH` | - | theHarvester path |

## Investigation Bundles

Run comprehensive investigations with presets:

| Preset | Description |
|--------|-------------|
| `quick` | Fastest useful check |
| `balanced` | Good default for analysis |
| `deep` | Broader investigation |

Role profiles:

| Profile | Summary Style |
|---------|---------------|
| `analyst` | Evidence-focused operational |
| `executive` | Business impact focus |
| `cto` | Leadership/risk focus |
| `red-team-lab` | Deep collection mode |

## Claude Desktop Configuration

Use one of the templates in `config/`:
- `claude_desktop_config.windows.example.json`
- `claude_desktop_config.linux.example.json`
- `config/claude_desktop_config.kali_bridge.example.json`

## Preflight Checks

```bash
python src/self_test.py
python src/self_test.py --json  # Machine-readable
python src/self_test.py --strict-optional  # Fail on missing optional
```

## Docker

```bash
docker build -t osint-mcp-enterprise-gateway .
docker run -p 9090:9090 -p 9091:9091 osint-mcp-enterprise-gateway
```

## Directory Structure

```
osint-mcp-enterprise-gateway/
├── src/
│   ├── osint_tools_mcp_server.py   # Main MCP server
│   ├── cache.py                    # Result caching
│   ├── models.py                   # Output normalization
│   ├── validators.py               # Input validation
│   ├── metrics.py                  # Prometheus metrics
│   ├── jobs.py                     # Async job queue
│   ├── exporters.py                # Export generators
│   ├── dashboard.py               # HTTP dashboard
│   └── self_test.py               # Preflight checks
├── config/                         # Claude Desktop templates
├── scripts/                       # Setup scripts
├── tests/                         # Test suite
├── docs/                          # Documentation
├── requirements.txt               # Core dependencies
├── requirements-optional.txt      # Optional dependencies
├── Dockerfile                     # Docker image
├── docker-compose.yml            # Docker Compose
├── package.json                  # npm metadata
└── CLAUDE.md                     # Project plan
```

## License

MIT License - See LICENSE file for details.

## Disclaimer

Use only for lawful, authorized, and ethical security research and OSINT workflows.
