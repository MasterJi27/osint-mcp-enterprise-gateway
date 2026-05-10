# OSINT MCP Enterprise Gateway - Implementation Plan

## Production Features to Implement

### Phase 1: Core Infrastructure
- [ ] Result Caching with SHA256-based deduplication
- [ ] Output Normalization to common OSINT schema
- [ ] Input Validation & Sanitization

### Phase 2: Enterprise Controls
- [ ] Enhanced Safe Mode (dry-run, per-tool allowlists)
- [ ] Target expansion detection
- [ ] Comprehensive audit logging

### Phase 3: Observability
- [ ] Structured metrics with Prometheus endpoint
- [ ] Request latency tracking
- [ ] Tool success/failure rates

### Phase 4: Output & Export
- [ ] PDF export with branding
- [ ] CSV export for analysis
- [ ] JSON Schema validation

### Phase 5: Async & Dashboard
- [ ] Job queue for long-running scans
- [ ] Simple HTTP dashboard
- [ ] Auto-generated API docs

## Architecture

```
src/
├── osint_tools_mcp_server.py   # Main MCP server
├── cache.py                     # Result caching layer
├── models.py                    # Output normalization schemas
├── validators.py                # Input validation
├── metrics.py                   # Prometheus metrics
├── jobs.py                     # Async job queue
├── dashboard.py                 # HTTP dashboard
└── exporters.py                # Export generators
```
