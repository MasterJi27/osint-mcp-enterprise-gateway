# User Prompts for AI Assistant - OSINT MCP Enterprise Gateway

A comprehensive guide for users to interact with AI assistants using this OSINT gateway.

---

## Quick Start Prompts

### For New Users

```
You're working with the OSINT MCP Enterprise Gateway. I need to:
1. Check the system health and available tools
2. Understand what tools are ready to use
3. Get started with a basic username search

What should I do first?
```

```
Show me the server health status and explain what tools are available for my investigation.
```

### Basic Investigation

```
I want to investigate the username "johndoe" - can you run the appropriate OSINT tools
and give me a summary of findings?
```

```
Check if the email "john.doe@example.com" is registered on any social media platforms.
```

```
Gather information about the domain "example.com" including emails, hosts, and subdomains.
```

---

## Investigation Prompts by Target Type

### Email Investigation Prompts

```
Search for information about: testuser@gmail.com
- Check which services this email is registered on
- Look for any Google account associations
- Check for data breaches
```

```
I need a comprehensive email investigation for "analyst@company.com":
- Run the deep investigation bundle
- Use the analyst role profile
- Generate a report-ready summary
```

```
Quick check: Is "newuser@yahoo.com" registered on any platforms? Just the quick scan.
```

```
Full email OSINT on "target@domain.com":
- Use deep preset
- Include all available tools
- Export results to markdown
```

### Username Investigation Prompts

```
Find all social media accounts for username "cooluser123"
```

```
Run a comprehensive username search for "johndoe":
- Use Sherlock first for quick results
- Then use Maigret for deeper enumeration
- Cross-reference findings
```

```
I need to find this username across as many platforms as possible. Use deep investigation mode.
Username: "investigator_pro"
```

```
Quick username sweep for "testuser" - just the fast tools, no deep scan.
```

### Domain Investigation Prompts

```
Gather intelligence on "targetdomain.com":
- Find associated emails
- Discover hosts and subdomains
- Identify any exposed services
```

```
Run a SpiderFoot scan on "example.com" to get comprehensive domain reconnaissance.
```

```
Domain OSINT on "suspicious-site.net":
- Use balanced preset
- Include theHarvester for email discovery
- Check for any security issues
```

```
I need to investigate a domain for a security assessment:
Target: "test-domain.com"
Preset: deep
Role: red-team-lab
```

---

## Workflow-Specific Prompts

### Triage & Discovery

```
I'm not sure what type of target this is: "user123@example.com"
Can you triage it and recommend the next steps?
```

```
What tools would you recommend for investigating an email address?
```

```
Help me understand what I'm dealing with: should I investigate this as an email, username, or domain?
Target: "myaccount"
```

### Investigation Bundles

```
Run a balanced investigation on "target@example.com" and give me a professional report.
```

```
Use the executive role profile to summarize findings for "username" - keep it concise and business-focused.
```

```
I need a comprehensive investigation for my security report:
- Target: "investigation_target.com"
- Preset: deep
- Role: analyst
- Generate detailed findings with confidence scores
```

### Cross-Tool Correlation

```
After running Sherlock on "username", cross-reference with Maigret to find any additional platforms.
```

```
Compare findings from both Holehe and GHunt for "email@target.com" to get a complete picture.
```

```
Run all username tools (Sherlock, Maigret, Blackbird) in parallel on "targetuser",
then correlate the results to identify confirmed accounts.
```

### Documentation & Reporting

```
Generate a case summary for my investigation on "target".
Include findings from Sherlock and theHarvester.
```

```
Export my investigation results to markdown format for a security report.
Target: "example.com"
Tools used: theHarvester, SpiderFoot
```

```
Create a professional report from the OSINT findings:
- Target: "investigation.com"
- Include all tool results
- Format for executive presentation
- Export to PDF
```

---

## Advanced Usage Prompts

### Safe Mode Investigation

```
I want to investigate "example.com" but only scan the allowed targets list.
Enable safe mode and run the investigation.
```

```
Run investigation in dry-run mode first to see what would be executed,
then confirm before running the actual scan.
```

### Rate-Limited Batch Operations

```
I need to investigate 10 email addresses, but I want to respect rate limits.
Process these one at a time:
1. test1@example.com
2. test2@example.com
...and so on
```

### Cached Results

```
Check if we already have results for "famoususer" in the cache.
If cached, show me the results. If not, run the investigation.
```

```
Clear the cache and start fresh for a new investigation cycle.
```

### Tool-Specific Prompts

```
Use SpiderFoot to scan "target.com" for all data types and return JSON results.
```

```
Run theHarvester on "domain.com" with only Google and Bing as sources, limit 100 results.
```

```
Use GHunt to check if "gmail_account@gmail.com" has an associated Google profile.
```

---

## Role-Specific Prompts

### For Security Analysts

```
I'm a security analyst. Run a balanced investigation on "target@company.com"
and focus on evidence quality and cross-tool correlation.
```

```
Investigation request:
- Target: suspicious@email.com
- Type: Email investigation
- Priority: High
- Deliverable: Evidence report with confidence scores
```

```
I need operational intelligence on "username":
- Run all available tools
- Focus on finding correlations between platforms
- Document all negative results too
```

### For Executives

```
Run a quick scan on "competitor.com" and give me a 1-paragraph executive summary
of the key findings and business risk.
```

```
Executive brief requested:
- Target: "company.com"
- Focus: Business impact and risk
- Format: Concise summary
- Time limit: Quick preset only
```

```
Give me a high-level overview of "username"'s online presence.
Don't go too deep, just the key findings.
```

### For CTO/CISO

```
Security posture assessment for "targetcompany.com":
- Use the CTO role profile
- Identify exposed attack surface
- Assess risk level
- Recommend remediation priorities
```

```
I need to evaluate our external attack surface.
Scan "ourdomain.com" and rate the security findings by severity.
```

### For Red Team/Lab Use

```
Full reconnaissance on "target.com":
- Use red-team-lab profile
- Deep scan with all available tools
- Include raw outputs
- Enable maximum verbosity
```

```
Lab investigation:
- Target: "lab-target.com"
- Preset: deep
- Role: red-team-lab
- Save all intermediate results
- Generate reproducible methodology report
```

---

## Quick Reference Templates

### Template 1: Basic Investigation
```
Investigate [TARGET] using [TOOL/BUNDLE] and summarize findings.
```

### Template 2: Comprehensive Investigation
```
Run a [PRESET] investigation on [TARGET] using the [ROLE] profile.
Generate a [FORMAT] report with [SPECIFIC REQUIREMENTS].
```

### Template 3: Tool-Specific Scan
```
Use [TOOL_NAME] to [ACTION] on [TARGET] with [PARAMETERS].
```

### Template 4: Comparison/Correlation
```
Run [TOOL_1] and [TOOL_2] on [TARGET], then cross-reference findings.
```

### Template 5: Batch Investigation
```
Investigate the following targets, respecting rate limits:
1. [TARGET_1]
2. [TARGET_2]
3. [TARGET_3]
```

---

## Example Conversations

### Example 1: New User Getting Started
```
USER: I'm new to this. How do I start an investigation?

ASSISTANT: Let me first check our system health and available tools:

osint_server_health()

Then I can recommend the best approach based on what you want to investigate.

What type of target are you looking into - an email, username, or domain?
```

### Example 2: Email Investigation
```
USER: I need to investigate "john.smith@company.com"

ASSISTANT: I'll run a comprehensive email investigation. Based on the target type,
I'll use the balanced investigation bundle with the analyst profile.

osint_investigation_bundle(
    target="john.smith@company.com",
    preset="balanced",
    role_profile="analyst"
)

This will:
1. Run Holehe to find registered services
2. Run GHunt for Google account correlation
3. Generate a case summary

Shall I proceed?
```

### Example 3: Domain Reconnaissance
```
USER: Full domain scan on "targetdomain.com" for security assessment

ASSISTANT: Running deep investigation with red-team-lab profile for comprehensive
reconnaissance.

osint_investigation_bundle(
    target="targetdomain.com",
    preset="deep",
    role_profile="red-team-lab"
)

This will:
- Run theHarvester for email/host discovery
- Run SpiderFoot for comprehensive scan
- Include all raw outputs
- Generate detailed methodology report

Results will include:
- Associated emails
- Hosts and subdomains
- Exposed services
- Potential vulnerabilities
```

### Example 4: Quick Triage
```
USER: What's this target: "weird_input_123"?

ASSISTANT: Let me triage this to understand what we're dealing with:

osint_target_triage(
    target="weird_input_123",
    run_checks=false
)

This will tell us if it's an email, username, or domain, and recommend the best tools.
```

### Example 5: Report Generation
```
USER: Generate a security report from my investigation results

ASSISTANT: I'll create a professional markdown report from your findings.

osint_case_summary(
    title="Security Assessment: Target Investigation",
    target="target.com",
    target_kind="domain",
    tool_results={
        "theHarvester": {...},
        "SpiderFoot": {...}
    },
    analyst_notes="High confidence findings on exposed email servers."
)

Then export it:

osint_export_artifact(
    title="Security_Assessment_Target_2024",
    content={...},
    output_dir="reports",
    format="markdown"
)
```

---

## Prompts for Tool Management

### Cache Management
```
Check the cache statistics and tell me our hit rate.
```

```
Clear all cached results - starting fresh investigation cycle.
```

```
How many results do we have cached? What's the average hit rate?
```

### Metrics & Monitoring
```
Show me Prometheus metrics for the last hour.
```

```
Get server health status and tool availability.
```

```
What's our current rate limit status? How many requests today?
```

### Configuration
```
Enable safe mode and set allowed targets to "example.com" only.
```

```
Put the server in dry-run mode for testing.
```

```
Update the tool allowlist to only include Sherlock and Holehe.
```

---

## Common Use Case Prompts

### Use Case 1: Brand Protection
```
I need to monitor for fake accounts using our brand name "MyBrand".
Search for "mybrand" across all platforms and report any suspicious accounts.
```

### Use Case 2: Due Diligence
```
Run a background check on "candidate_name" - search all platforms
and provide a comprehensive online presence report.
```

### Use Case 3: Incident Response
```
URGENT: I'm investigating a phishing campaign.
The suspicious domain is "phish-link.com".
Run a quick scan and tell me:
- When was it registered
- What servers it's hosted on
- Any associated email addresses
- How recently it was created
```

### Use Case 4: Attack Surface Assessment
```
Assess the external attack surface for "mycompany.com".
- Find all exposed services
- Identify potential entry points
- Rate severity of findings
```

### Use Case 5: Person of Interest
```
Research: "John Doe" (potential employee misconduct)
- Find all social media accounts
- Check for data breaches
- Look for associated email patterns
- Cross-reference any findings
```

---

## Best Practices Prompts

### Do This
```
Start with triage to identify the target type before running tools.
```

```
Use investigation bundles for comprehensive scans to save time.
```

```
Check health status before starting major investigations.
```

```
Enable safe mode when investigating targets outside your scope.
```

### Avoid This
```
Don't run all tools on every target - match tools to your investigation goals.
```

```
Don't ignore rate limits - space out bulk investigations.
```

```
Don't skip the health check before critical investigations.
```

---

## Emergency/Urgent Investigation

```
URGENT INVESTIGATION REQUIRED:
Target: [SUSPICIOUS_TARGET]
Priority: CRITICAL
Run: Deep investigation, all available tools
Report: Immediate executive summary

What tools are available right now?
```

---

## Tips for Better Results

1. **Be Specific**: Instead of "investigate this email", say "find all accounts registered with this email"

2. **Set Context**: "I'm investigating a potential data breach" helps prioritize findings

3. **Specify Format**: "Export as CSV for spreadsheet analysis" ensures you get usable output

4. **Indicate Urgency**: "URGENT" prompts get immediate attention to tool availability

5. **Mention Role**: "I'm presenting to executives" triggers more concise output

6. **Request Confidence Levels**: "Include confidence scores" helps prioritize findings

---

## Summary Cheat Sheet

| Investigation Type | Prompt Template |
|-------------------|-----------------|
| Quick check | `Quick scan on [TARGET]` |
| Full investigation | `Deep investigation on [TARGET]` |
| Email research | `Investigate email [EMAIL]` |
| Username search | `Find username [USERNAME] everywhere` |
| Domain recon | `Domain intelligence on [DOMAIN]` |
| Report needed | `Generate [FORMAT] report on [TARGET]` |
| Executive brief | `Executive summary on [TARGET]` |
| Security assessment | `Attack surface assessment for [DOMAIN]` |
| Tool status | `Server health check` |
| Cache check | `Show cache statistics` |

---

*This guide helps users get the most out of the OSINT MCP Enterprise Gateway through clear, actionable prompts.*
