#!/usr/bin/env python3
"""
System prompts and usage guidance for OSINT MCP Enterprise Gateway.
Provides efficient usage patterns and best practices.
"""

from typing import Dict, List, Optional


SYSTEM_PROMPT = """You are an OSINT investigation assistant powered by the OSINT MCP Enterprise Gateway.

## Available Tools

| Tool | Purpose | Best For |
|------|---------|---------|
| `osint_target_triage` | Auto-detect target type | Unknown input types |
| `sherlock_username_search` | Username search | Quick username checks |
| `holehe_email_search` | Email detection | Email verification |
| `maigret_username_search` | Deep username enum | Comprehensive username search |
| `theharvester_domain_search` | Domain intelligence | Email/host discovery |
| `spiderfoot_scan` | Full domain scan | Complete reconnaissance |
| `ghunt_google_search` | Google account | Gmail account research |
| `blackbird_username_search` | Fast username OSINT | Quick username sweep |
| `osint_investigation_bundle` | Preset workflows | One-click investigations |
| `osint_case_summary` | Report generation | Creating reports |
| `osint_export_artifact` | Multi-format export | Sharing results |
| `osint_server_health` | System status | Pre-flight checks |

## Efficiency Patterns

### Pattern 1: Quick Triage First
When unsure about a target type, always start with triage:
```
osint_target_triage(target="@user.com", run_checks=false)
```
This returns recommendations without making external requests.

### Pattern 2: Investigation Bundles
For complete investigations, use bundles instead of individual tools:
```
osint_investigation_bundle(target="@user.com", preset="balanced", role_profile="analyst")
```
This runs multiple tools in parallel and generates a summary.

### Pattern 3: Caching Strategy
- First scan: Full tool execution
- Repeat scans: Cached results returned instantly
- Force refresh: Check cache status and clear if needed

### Pattern 4: Role-Based Investigations
Choose the right preset for your context:
- `quick` - Time-sensitive checks, initial reconnaissance
- `balanced` - Standard investigations, most reliable
- `deep` - Comprehensive research, false positive reduction

### Pattern 5: Tool Selection by Target Type

**Email Investigation:**
1. `holehe_email_search` - Fast email verification
2. `ghunt_google_search` - Google account correlation
3. Bundle with `preset="deep"` for complete picture

**Username Investigation:**
1. `sherlock_username_search` - Quick social media check
2. `maigret_username_search` - Deep enumeration (slower but thorough)
3. `blackbird_username_search` - Additional coverage
4. Bundle with `preset="balanced"` for most platforms

**Domain Investigation:**
1. `theharvester_domain_search` - Quick email/host discovery
2. `spiderfoot_scan` - Comprehensive scan (slower but thorough)
3. Bundle with `preset="deep"` for complete reconnaissance

## Best Practices

### Do's
- Start with triage for unknown targets
- Use investigation bundles for complete investigations
- Enable safe mode in production
- Use rate limiting for batch operations
- Export results for documentation
- Validate targets before scanning

### Don'ts
- Don't run all tools on every target
- Don't ignore rate limits on external services
- Don't skip the health check before major operations
- Don't scan without understanding legal implications
- Don't share results without proper authorization

## Investigation Workflow

```
1. Health Check
   └─> osint_server_health()
       └─> Verify tools available

2. Target Triage
   └─> osint_target_triage(target, run_checks=false)
       └─> Identify target type

3. Initial Scan
   └─> Use recommended tool OR investigation_bundle()
       └─> Collect initial results

4. Correlation
   └─> Run secondary tools for cross-validation
       └─> Compare findings

5. Documentation
   └─> osint_case_summary()
       └─> osint_export_artifact()
           └─> Save report

6. Validation
   └─> Manually verify high-confidence findings
       └─> Document evidence
```

## Advanced Features

### Dry Run Mode
Test workflows without execution:
```
OSINT_DRY_RUN_MODE=true
```
All tools return what WOULD be executed.

### Tool Allowlisting
Restrict tools for specific use cases:
```
OSINT_TOOL_ALLOWLIST=sherlock_username_search,holehe_email_search
```

### Target Allowlisting
Enterprise target scoping:
```
OSINT_SAFE_MODE=true
OSINT_ALLOWED_TARGETS=example.com,trusted.org
```

### Result Caching
Results are cached for 1 hour by default:
- Cache hit = instant response
- Cache miss = full tool execution
- Clear cache with osint_cache_status(clear=true)

## Output Formats

| Format | Use Case |
|--------|----------|
| `markdown` | Reports, documentation, sharing |
| `json` | API integration, automation |
| `csv` | Spreadsheet analysis, bulk operations |
| `pdf` | Formal reports, presentations |

## Rate Limits

Default: 60 requests/minute per API key

For batch operations:
- Space out large scans
- Use investigation bundles (parallel execution)
- Enable caching for repeated targets

## Legal Disclaimer

Always ensure:
- You have authorization for the target
- Your use case is legal in your jurisdiction
- You comply with platform terms of service
- You follow responsible disclosure practices
"""


EFFICIENCY_TIPS = [
    {
        "tip": "Use triage first",
        "description": "Always start with osint_target_triage for unknown targets to get recommendations without making external requests.",
        "savings": "5-30 seconds per investigation",
    },
    {
        "tip": "Batch with bundles",
        "description": "Use osint_investigation_bundle instead of running tools individually. It parallelizes execution and generates summaries.",
        "savings": "50-70% faster than sequential execution",
    },
    {
        "tip": "Leverage caching",
        "description": "Identical targets within 1 hour return cached results instantly. Check cache status before rescanning.",
        "savings": "Near-instant for repeated targets",
    },
    {
        "tip": "Choose the right preset",
        "description": "quick=fastest, balanced=recommended, deep=most thorough. Match preset to investigation needs.",
        "savings": "Avoid over-scanning or under-scanning",
    },
    {
        "tip": "Use role profiles",
        "description": "analyst=evidence focus, executive=business impact, cto=risk focus, red-team-lab=comprehensive.",
        "savings": "Tailored output for your audience",
    },
]


QUICK_START_PROMPTS = {
    "username_check": """Check if a username exists on social media:
Tool: sherlock_username_search
Input: username="targetuser"
Output: List of platforms where username exists""",

    "email_check": """Verify if an email is registered on services:
Tool: holehe_email_search
Input: email="target@example.com"
Output: List of services where email is registered""",

    "domain_recon": """Gather intelligence about a domain:
Tool: osint_investigation_bundle
Input: target="example.com", preset="balanced", role_profile="analyst"
Output: Comprehensive domain report with emails, hosts, and related domains""",

    "full_investigation": """Complete OSINT investigation:
Tool: osint_investigation_bundle
Input: target="target", preset="deep", role_profile="analyst"
Output: Complete investigation with all available tools and markdown summary""",

    "quick_triage": """Identify what type of target you have:
Tool: osint_target_triage
Input: target="something", run_checks=false
Output: Target type and recommended next steps""",
}


ROLE_GUIDANCE = {
    "analyst": {
        "name": "Security Analyst",
        "focus": "Evidence quality, correlation, operational use",
        "preset": "balanced",
        "output": "Detailed findings with confidence scores",
        "best_for": "Day-to-day investigations, threat intel",
    },
    "executive": {
        "name": "Executive",
        "focus": "Business impact, risk summary, recommendations",
        "preset": "quick",
        "output": "Concise summary with key findings",
        "best_for": "Leadership updates, board reports",
    },
    "cto": {
        "name": "CTO / CISO",
        "focus": "Risk posture, coverage assessment, strategic recommendations",
        "preset": "quick",
        "output": "Executive summary with risk indicators",
        "best_for": "Security strategy, compliance reporting",
    },
    "red-team-lab": {
        "name": "Red Team / Lab",
        "focus": "Comprehensive data collection, reproducible methodology",
        "preset": "deep",
        "output": "Full raw data with metadata, ready for further analysis",
        "best_for": "Authorized testing, research, tool development",
    },
}


def get_system_prompt() -> str:
    """Returns the complete system prompt for OSINT usage."""
    return SYSTEM_PROMPT


def get_efficiency_tips() -> List[Dict[str, str]]:
    """Returns efficiency optimization tips."""
    return EFFICIENCY_TIPS


def get_quick_start_prompts() -> Dict[str, str]:
    """Returns quick-start prompt templates."""
    return QUICK_START_PROMPTS


def get_role_guidance() -> Dict[str, Dict[str, str]]:
    """Returns role-based investigation guidance."""
    return ROLE_GUIDANCE


def get_investigation_template(
    target: str,
    target_type: Optional[str] = None,
    role: str = "analyst"
) -> Dict[str, any]:
    """Generate an investigation template based on target and role."""

    if not target_type:
        templates = {
            "email": {
                "tools": ["holehe_email_search", "ghunt_google_search"],
                "bundle": "balanced",
                "questions": [
                    "What services is this email registered on?",
                    "Is this email associated with any Google accounts?",
                    "Are there any data breaches associated with this email?",
                ],
            },
            "username": {
                "tools": ["sherlock_username_search", "maigret_username_search"],
                "bundle": "balanced",
                "questions": [
                    "What platforms is this username active on?",
                    "Are there similar usernames that might be the same person?",
                    "What information can be correlated across platforms?",
                ],
            },
            "domain": {
                "tools": ["theharvester_domain_search", "spiderfoot_scan"],
                "bundle": "deep",
                "questions": [
                    "What emails are associated with this domain?",
                    "What hosts and subdomains are publicly accessible?",
                    "Are there any exposed services or vulnerabilities?",
                ],
            },
            "unknown": {
                "tools": ["osint_target_triage"],
                "bundle": "quick",
                "questions": [
                    "What type of target is this?",
                    "What tools are recommended for further investigation?",
                ],
            },
        }
        target_type = "unknown"

    return {
        "target": target,
        "target_type": target_type,
        "role": role,
        "next_steps": [
            "Run osint_server_health() to verify tool availability",
            "Run osint_target_triage() if target type is unknown",
            f"Execute investigation bundle with {role} profile",
            "Review and correlate findings",
            "Run secondary tools for cross-validation",
            "Generate case summary",
            "Export to desired format",
        ],
    }
