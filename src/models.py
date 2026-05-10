#!/usr/bin/env python3
"""
Output Normalization Schemas for OSINT MCP Enterprise Gateway.
Provides common schema for all tool outputs.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ConfidenceLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ResultStatus(Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    PENDING = "pending"
    TIMEOUT = "timeout"


@dataclass
class SocialAccount:
    platform: str
    url: Optional[str] = None
    username: Optional[str] = None
    user_id: Optional[str] = None
    profile_picture: Optional[str] = None
    bio: Optional[str] = None
    followers: Optional[int] = None
    following: Optional[int] = None
    posts: Optional[int] = None
    verified: Optional[bool] = None
    created_at: Optional[str] = None
    last_updated: Optional[str] = None
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class EmailInfo:
    service: Optional[str] = None
    username: Optional[str] = None
    domain: Optional[str] = None
    email_verified: Optional[bool] = None
    associated_accounts: List[str] = field(default_factory=list)
    profile_links: List[str] = field(default_factory=list)
    breach_records: List[str] = field(default_factory=list)
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DomainInfo:
    registrar: Optional[str] = None
    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    dns_records: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class OSINTResult:
    tool: str
    target: str
    target_kind: str
    status: str
    found: bool
    accounts: List[SocialAccount] = field(default_factory=list)
    email_info: Optional[EmailInfo] = None
    domain_info: Optional[DomainInfo] = None
    raw_output: Optional[str] = None
    error_message: Optional[str] = None
    confidence: str = ConfidenceLevel.UNKNOWN.value
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    execution_time_ms: Optional[float] = None
    sites_checked: int = 0
    sites_found: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "tool": self.tool,
            "target": self.target,
            "target_kind": self.target_kind,
            "status": self.status,
            "found": self.found,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "execution_time_ms": self.execution_time_ms,
            "sites_checked": self.sites_checked,
            "sites_found": self.sites_found,
            "metadata": self.metadata,
        }

        if self.accounts:
            result["accounts"] = [a.to_dict() for a in self.accounts]
        if self.email_info:
            result["email_info"] = self.email_info.to_dict()
        if self.domain_info:
            result["domain_info"] = self.domain_info.to_dict()
        if self.raw_output:
            result["raw_output"] = self.raw_output
        if self.error_message:
            result["error_message"] = self.error_message

        return result


class OSINTNormalizer:
    """Converts raw tool outputs to normalized OSINTResult format."""

    @staticmethod
    def normalize_sherlock(
        raw_output: str,
        target: str,
        execution_time_ms: Optional[float] = None,
    ) -> OSINTResult:
        accounts: List[SocialAccount] = []
        found_count = 0
        sites_checked = 0

        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            if "[+]" in line or "http" in line.lower():
                parts = line.split("[+]", 1) if "[+]" in line else [line, line]
                platform = parts[0].replace("[+]", "").strip()
                url = parts[1].strip() if len(parts) > 1 else None

                if url and "http" in url.lower():
                    accounts.append(SocialAccount(platform=platform, url=url))
                    found_count += 1
                sites_checked += 1

        return OSINTResult(
            tool="sherlock",
            target=target,
            target_kind="username",
            status=ResultStatus.FOUND.value if found_count > 0 else ResultStatus.NOT_FOUND.value,
            found=found_count > 0,
            accounts=accounts,
            raw_output=raw_output[:10000],
            confidence=ConfidenceLevel.HIGH.value if found_count > 5 else ConfidenceLevel.MEDIUM.value if found_count > 0 else ConfidenceLevel.LOW.value,
            execution_time_ms=execution_time_ms,
            sites_checked=sites_checked,
            sites_found=found_count,
        )

    @staticmethod
    def normalize_holehe(
        raw_output: str,
        target: str,
        execution_time_ms: Optional[float] = None,
    ) -> OSINTResult:
        accounts: List[SocialAccount] = []
        email_info = EmailInfo()

        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            if any(x in line.lower() for x in ["[+]", "[x]", "used"]):
                parts = line.split()
                if parts:
                    platform = parts[0].replace("[+]", "").replace("[x]", "").strip()
                    if platform and len(platform) > 1:
                        accounts.append(SocialAccount(platform=platform))

        email_parts = target.split("@")
        if len(email_parts) == 2:
            email_info.username = email_parts[0]
            email_info.domain = email_parts[1]

        return OSINTResult(
            tool="holehe",
            target=target,
            target_kind="email",
            status=ResultStatus.FOUND.value if accounts else ResultStatus.NOT_FOUND.value,
            found=bool(accounts),
            accounts=accounts,
            email_info=email_info,
            raw_output=raw_output[:10000],
            confidence=ConfidenceLevel.HIGH.value if len(accounts) > 3 else ConfidenceLevel.MEDIUM.value if accounts else ConfidenceLevel.LOW.value,
            execution_time_ms=execution_time_ms,
            sites_checked=len(accounts),
            sites_found=len(accounts),
        )

    @staticmethod
    def normalize_theharvester(
        raw_output: str,
        target: str,
        execution_time_ms: Optional[float] = None,
    ) -> OSINTResult:
        emails: List[str] = []
        hosts: List[str] = []
        ip_addresses: List[str] = []

        lines = raw_output.strip().split("\n")
        current_section = ""

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if "emails:" in line.lower():
                current_section = "emails"
            elif "hosts:" in line.lower() or "hosts found" in line.lower():
                current_section = "hosts"
            elif any(x in line for x in ["[*]", "[+]"]):
                value = line.split("]", 1)[-1].strip() if "]" in line else line
                if "@" in value and "." in value:
                    emails.append(value)
                elif not value.startswith("http"):
                    hosts.append(value)

        return OSINTResult(
            tool="theharvester",
            target=target,
            target_kind="domain",
            status=ResultStatus.FOUND.value if (emails or hosts) else ResultStatus.NOT_FOUND.value,
            found=bool(emails or hosts),
            domain_info=DomainInfo(
                emails=emails,
                hosts=hosts,
                ip_addresses=ip_addresses,
            ),
            raw_output=raw_output[:10000],
            confidence=ConfidenceLevel.HIGH.value if len(emails) > 3 else ConfidenceLevel.MEDIUM.value if emails else ConfidenceLevel.LOW.value,
            execution_time_ms=execution_time_ms,
            sites_checked=len(emails) + len(hosts),
            sites_found=len(emails) + len(hosts),
        )

    @staticmethod
    def normalize_spiderfoot(
        raw_output: str,
        target: str,
        execution_time_ms: Optional[float] = None,
    ) -> OSINTResult:
        try:
            import json as json_module
            data = json_module.loads(raw_output)
            accounts: List[SocialAccount] = []
            emails: List[str] = []
            domains: List[str] = []

            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        module = item.get("type", "")
                        data_value = item.get("data", "")
                        if isinstance(data_value, list):
                            data_value = data_value[0] if data_value else ""

                        if "email" in module.lower() and "@" in str(data_value):
                            emails.append(str(data_value))
                        elif "social media" in module.lower() or "username" in module.lower():
                            accounts.append(SocialAccount(platform=module, additional_info={"data": data_value}))
                        elif "domain" in module.lower():
                            domains.append(str(data_value))

            return OSINTResult(
                tool="spiderfoot",
                target=target,
                target_kind="domain",
                status=ResultStatus.FOUND.value if (emails or accounts or domains) else ResultStatus.NOT_FOUND.value,
                found=bool(emails or accounts or domains),
                accounts=accounts,
                domain_info=DomainInfo(emails=emails, subdomains=domains),
                raw_output=raw_output[:10000],
                confidence=ConfidenceLevel.HIGH.value,
                execution_time_ms=execution_time_ms,
                metadata={"modules_run": len(data) if isinstance(data, list) else 0},
            )
        except (json_module.JSONDecodeError, TypeError, ImportError):
            return OSINTResult(
                tool="spiderfoot",
                target=target,
                target_kind="domain",
                status=ResultStatus.ERROR.value,
                found=False,
                raw_output=raw_output[:10000],
                confidence=ConfidenceLevel.UNKNOWN.value,
                execution_time_ms=execution_time_ms,
                error_message="Failed to parse SpiderFoot JSON output",
            )

    @staticmethod
    def normalize_maigret(
        raw_output: str,
        target: str,
        execution_time_ms: Optional[float] = None,
    ) -> OSINTResult:
        accounts: List[SocialAccount] = []
        found_count = 0

        try:
            import json as json_module
            data = json_module.loads(raw_output)

            if isinstance(data, dict):
                for platform, info in data.items():
                    if isinstance(info, dict) and info.get("status") == "ok":
                        accounts.append(SocialAccount(
                            platform=platform,
                            url=info.get("url"),
                            additional_info=info,
                        ))
                        found_count += 1
        except (json_module.JSONDecodeError, TypeError, ImportError):
            for line in raw_output.strip().split("\n"):
                if "[+]" in line or "http" in line.lower():
                    parts = line.split("[+]", 1) if "[+]" in line else [line, line]
                    platform = parts[0].replace("[+]", "").strip()
                    if platform:
                        accounts.append(SocialAccount(platform=platform))
                        found_count += 1

        return OSINTResult(
            tool="maigret",
            target=target,
            target_kind="username",
            status=ResultStatus.FOUND.value if found_count > 0 else ResultStatus.NOT_FOUND.value,
            found=found_count > 0,
            accounts=accounts,
            raw_output=raw_output[:10000],
            confidence=ConfidenceLevel.HIGH.value if found_count > 10 else ConfidenceLevel.MEDIUM.value if found_count > 0 else ConfidenceLevel.LOW.value,
            execution_time_ms=execution_time_ms,
            sites_checked=len(accounts),
            sites_found=found_count,
        )

    @staticmethod
    def normalize_ghunt(
        raw_output: str,
        target: str,
        execution_time_ms: Optional[float] = None,
    ) -> OSINTResult:
        email_info = EmailInfo()

        email_parts = target.split("@")
        if len(email_parts) == 2:
            email_info.username = email_parts[0]
            email_info.domain = email_parts[1]
            email_info.service = email_parts[1].split(".")[0].capitalize() if "." in email_parts[1] else email_parts[1]

        accounts: List[SocialAccount] = []

        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            if any(x in line for x in ["[+]", "[*]", "youtube", "twitter", "github", "instagram"]):
                parts = line.split("]", 1)[-1].strip() if "]" in line else line
                if parts and len(parts) > 1:
                    accounts.append(SocialAccount(platform=parts[0].lower() if not parts[0].startswith("[") else parts[0], additional_info={"data": parts[1]}))

        return OSINTResult(
            tool="ghunt",
            target=target,
            target_kind="email",
            status=ResultStatus.FOUND.value if accounts else ResultStatus.NOT_FOUND.value,
            found=bool(accounts),
            accounts=accounts,
            email_info=email_info,
            raw_output=raw_output[:10000],
            confidence=ConfidenceLevel.HIGH.value if len(accounts) > 2 else ConfidenceLevel.MEDIUM.value if accounts else ConfidenceLevel.LOW.value,
            execution_time_ms=execution_time_ms,
            sites_checked=len(accounts),
            sites_found=len(accounts),
        )

    @staticmethod
    def normalize_blackbird(
        raw_output: str,
        target: str,
        execution_time_ms: Optional[float] = None,
    ) -> OSINTResult:
        accounts: List[SocialAccount] = []
        found_count = 0

        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            if any(x in line for x in ["[+]", "Found", "found"]):
                parts = line.split(None, 1)
                if parts:
                    platform = parts[0].replace("[+]", "").replace("Found", "").strip()
                    if platform and len(platform) > 1:
                        accounts.append(SocialAccount(platform=platform))
                        found_count += 1

        return OSINTResult(
            tool="blackbird",
            target=target,
            target_kind="username",
            status=ResultStatus.FOUND.value if found_count > 0 else ResultStatus.NOT_FOUND.value,
            found=found_count > 0,
            accounts=accounts,
            raw_output=raw_output[:10000],
            confidence=ConfidenceLevel.HIGH.value if found_count > 5 else ConfidenceLevel.MEDIUM.value if found_count > 0 else ConfidenceLevel.LOW.value,
            execution_time_ms=execution_time_ms,
            sites_checked=len(accounts),
            sites_found=found_count,
        )

    @classmethod
    def normalize_tool_output(
        cls,
        tool_name: str,
        raw_output: str,
        target: str,
        execution_time_ms: Optional[float] = None,
    ) -> OSINTResult:
        normalizers = {
            "sherlock": cls.normalize_sherlock,
            "holehe": cls.normalize_holehe,
            "theharvester": cls.normalize_theharvester,
            "spiderfoot": cls.normalize_spiderfoot,
            "maigret": cls.normalize_maigret,
            "ghunt": cls.normalize_ghunt,
            "blackbird": cls.normalize_blackbird,
        }

        normalizer = normalizers.get(tool_name.lower())
        if normalizer:
            return normalizer(raw_output, target, execution_time_ms)

        return OSINTResult(
            tool=tool_name,
            target=target,
            target_kind="unknown",
            status=ResultStatus.ERROR.value,
            found=False,
            raw_output=raw_output[:10000] if raw_output else None,
            confidence=ConfidenceLevel.UNKNOWN.value,
            execution_time_ms=execution_time_ms,
            error_message=f"No normalizer available for tool: {tool_name}",
        )
