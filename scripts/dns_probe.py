"""Validation and planning helpers for read-only DNS probes."""

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit


_CAPABILITIES = ("dig", "kdig", "nslookup", "host", "resolvectl", "getent", "powershell")
_SHELL_METACHARACTERS = set(";&|`$<>\\'\"(){}[]*!")
_MARKDOWN_LINK = re.compile(r"\[(?P<label>[^\]]*)\]\((?P<href>[^)\s]*)\)")
_SCHEMA_VERSION = "1.0"
_IP_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]+")
_SECRET_NAME = re.compile(r"(?i)(token|secret|password|passphrase|credential|authorization|api[_-]?key)")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(token|secret|password|passphrase|credentials?|authorization|api[_-]?key)\s*=\s*[^\s&?#,;]+"
)
_URL_SUBSTRING = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_CLI_MAX_RESOLVERS = 6
_CLI_MAX_TIMEOUT_S = 10.0
_CLI_TOTAL_TIMEOUT_S = 20.0
_BASELINE_TOTAL_TIMEOUT_S = 90.0
_CLI_MAX_SAMPLES = 3
_AUTOMATIC_RECORD_TYPES = ("A", "AAAA", "NS", "SOA", "DS", "DNSKEY")
_HEALTH_CHECK_RECORD_TYPES = ("A", "AAAA", "NS", "SOA")
_PUBLIC_RESOLVERS = ("8.8.8.8", "180.76.76.76", "114.114.114.114")
_BASELINE_LAYERS = ("local", "dnssec", "public", "trace", "authoritative")
_LAYER_BUDGET_S = {
    "local": 20.0,
    "dnssec": 15.0,
    "public": 15.0,
    "trace": 20.0,
    "authoritative": 15.0,
}
_TRACE_TIMEOUT_S = 15.0
_MAX_AUTHORITATIVE_SERVERS = 3
_MAX_PARALLEL_PROBES = 8
_MAX_PARALLEL_PER_RESOLVER = 2
# Remote observation is the one step that sends anything off this machine, and it sends
# only the queried name and record type. Everything about it is pinned here so the
# disclosure is auditable in one place: one host, HTTPS only, no redirects, no
# credentials, bounded response, and a resolver fixed so that the answers different
# countries return are actually comparable with each other.
_REMOTE_API_HOST = "api.globalping.io"
_REMOTE_MEASUREMENT_URL = "https://api.globalping.io/v1/measurements"
_REMOTE_RESOLVER = "8.8.8.8"
_REMOTE_PROBES_PER_REGION = 2
_REMOTE_MAX_REGIONS = 4
_REMOTE_REQUEST_TIMEOUT_S = 10.0
_REMOTE_POLL_INTERVAL_S = 0.5
_REMOTE_TOTAL_BUDGET_S = 45.0
_REMOTE_MAX_RESPONSE_BYTES = 1000000
_REMOTE_RECORD_TYPES = ("A", "AAAA", "NS", "SOA", "DS", "DNSKEY")
_REGION_CODE = re.compile(r"^[A-Za-z]{2}$")
_SPECIAL_USE_SUFFIXES = (
    ".local", ".internal", ".lan", ".corp", ".home", ".intranet",
    ".test", ".invalid", ".localhost", ".private", ".example",
)
# Two-label public suffixes that appear in the targets this skill is used on.
# A miss only means the apex guess is one label off, which is reported, never hidden.
_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.au", "net.au", "org.au", "com.br", "com.mx", "com.tw", "com.hk",
    "com.sg", "co.kr", "co.in", "co.nz", "co.za",
})
_PREFLIGHT_FILE_LIMIT_BYTES = 65536
_VERSION_COMMANDS = {
    "dig": ["dig", "-v"],
    "kdig": ["kdig", "-V"],
    "nslookup": ["nslookup", "-version"],
    "host": ["host", "-V"],
    "resolvectl": ["resolvectl", "--version"],
    "getent": ["getent", "--version"],
    "powershell": None,
}


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_target(raw: str) -> dict:
    """Return a canonical hostname or IP literal without URL-only data."""
    if not isinstance(raw, str):
        raise ValueError("target must be text")

    value = raw.strip()
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("target must not be empty or contain control characters")

    # A target pasted from chat often arrives as a Markdown link. Unwrap it to the href
    # and let the checks below judge that, rather than rejecting the whole string.
    link = _MARKDOWN_LINK.fullmatch(value)
    if link:
        value = link.group("href").strip()
        if not value:
            raise ValueError("target must not be empty or contain control characters")

    is_url = "://" in value or value.startswith("//")
    if is_url:
        parsed = urlsplit(value)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs with credentials are not allowed")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("URL port must be numeric and in range") from exc
        if not parsed.hostname:
            raise ValueError("URL must include a hostname")
        candidate = parsed.hostname
    else:
        candidate = value

    bracketed_ipv6_authority = False
    if is_url and value.count("[") == 1 and value.count("]") == 1 and parsed.netloc.startswith("["):
        try:
            bracketed_ipv6_authority = ipaddress.ip_address(candidate).version == 6
        except ValueError:
            pass

    unsafe_characters = _SHELL_METACHARACTERS
    if bracketed_ipv6_authority:
        # The one bracket pair belongs to the URL authority, never argv data.
        unsafe_characters = _SHELL_METACHARACTERS - {"[", "]"}
    if any(char in unsafe_characters for char in value):
        raise ValueError("target contains unsafe characters")

    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        ip = None

    if ip is not None:
        address = str(ip)
        return {"input": address, "hostname": None, "ip": address, "is_url": is_url}

    if any(char in candidate for char in "/?:#@") or any(char.isspace() for char in candidate):
        raise ValueError("target must be a hostname or IP literal")
    try:
        hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("target hostname is not valid IDNA") from exc

    hostname = hostname.rstrip(".")
    if not hostname or len(hostname) > 253:
        raise ValueError("target hostname is invalid")
    labels = hostname.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           or not all(char.isalnum() or char == "-" for char in label) for label in labels):
        raise ValueError("target hostname is invalid")

    return {"input": hostname, "hostname": hostname, "ip": None, "is_url": is_url}


def detect_capabilities(
    platform_name: Optional[str] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> dict:
    """Report available probe executables using an injectable path lookup."""
    del platform_name
    return {name: bool(which(name)) for name in _CAPABILITIES}


def _validated_plan_target(target: dict) -> str:
    if not isinstance(target, dict):
        raise ValueError("target must be a mapping")
    hostname = target.get("hostname")
    address = target.get("ip")
    if bool(hostname) == bool(address):
        raise ValueError("target must contain exactly one hostname or IP")
    normalized = normalize_target(hostname or address)
    return normalized["hostname"] or normalized["ip"]


def _resolver_option(options: Optional[dict]) -> Optional[str]:
    if options is None:
        return None
    if not isinstance(options, dict):
        raise ValueError("options must be a mapping")
    resolver = options.get("resolver")
    if resolver is None:
        return None
    if not isinstance(resolver, str):
        raise ValueError("resolver must be an IP literal")
    try:
        return str(ipaddress.ip_address(resolver))
    except ValueError as exc:
        raise ValueError("resolver must be an IP literal") from exc


def _entry(
    identifier: str,
    purpose: str,
    argv: List[str],
    transport: str,
    resolver: str,
    qtype: str = "A",
    sample: int = 1,
    layer: str = "local",
    role: Optional[str] = None,
    qname: Optional[str] = None,
    timeout_s: Optional[float] = None,
) -> dict:
    entry = {
        "id": identifier,
        "purpose": purpose,
        "argv": argv,
        "transport": transport,
        "resolver": resolver,
        "qtype": qtype,
        "sample": sample,
        "layer": layer,
        "role": role or ("local" if transport == "local" else "recursive"),
    }
    if qname:
        # Set only when the query asks about a different name than the target,
        # such as the parent zone for DS or a nameserver's own address.
        entry["qname"] = qname
    if timeout_s is not None:
        entry["timeout_s"] = timeout_s
    return entry


def _apex_candidate(name: str) -> str:
    """Best-effort registrable zone for a hostname, used to place DS and DNSKEY queries."""
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _record_types_option(options: Optional[dict]) -> List[str]:
    raw = (options or {}).get("record_types", ["A"])
    if not isinstance(raw, (list, tuple)) or not raw:
        raise ValueError("record_types must be a non-empty list")
    record_types = []
    for value in raw:
        if not isinstance(value, str):
            raise ValueError("record types must be text")
        record_type = value.upper()
        if record_type not in _AUTOMATIC_RECORD_TYPES:
            raise ValueError("record type is not supported for automatic collection")
        if record_type not in record_types:
            record_types.append(record_type)
    return record_types


def _samples_option(options: Optional[dict]) -> int:
    value = (options or {}).get("samples", 1)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _CLI_MAX_SAMPLES:
        raise ValueError("samples must be an integer from 1 to {0}".format(_CLI_MAX_SAMPLES))
    return value


def _public_addresses_option(options: Optional[dict]) -> List[str]:
    raw = (options or {}).get("public_resolvers", _PUBLIC_RESOLVERS)
    if not isinstance(raw, (list, tuple)):
        raise ValueError("public_resolvers must be a list of IP literals")
    addresses = []
    for value in raw:
        if not isinstance(value, str):
            raise ValueError("public_resolvers must be a list of IP literals")
        try:
            address = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("public_resolvers must be a list of IP literals") from exc
        if address not in addresses:
            addresses.append(address)
    return addresses


def _planned_id(tool: str, transport: str, qtype: str, sample: int, multi_type: bool, samples: int) -> str:
    identifier = "{0}_{1}".format(tool, transport)
    if multi_type or qtype != "A":
        identifier += "_" + qtype.lower()
    if samples > 1:
        identifier += "_sample_{0}".format(sample)
    return identifier


def _layers_option(options: Optional[dict]) -> List[str]:
    raw = (options or {}).get("layers", ["local"])
    if not isinstance(raw, (list, tuple)) or not raw:
        raise ValueError("layers must be a non-empty list")
    layers = []
    for value in raw:
        if not isinstance(value, str) or value not in _BASELINE_LAYERS:
            raise ValueError(
                "layer must be one of: {0}".format(", ".join(_BASELINE_LAYERS))
            )
        if value not in layers:
            layers.append(value)
    if "local" not in layers:
        layers.insert(0, "local")
    return [layer for layer in _BASELINE_LAYERS if layer in layers]


def _resolver_slug(address: str) -> str:
    return re.sub(r"[^0-9a-z]+", "_", address.lower()).strip("_")


def _dnssec_layer_entries(
    name: str,
    resolver_address: Optional[str],
    resolver: str,
    validating_address: Optional[str] = None,
) -> List[dict]:
    """Queries that together decide whether signing exists and whether it validates."""
    server = ["@" + resolver_address] if resolver_address else []
    apex = _apex_candidate(name)
    entries = [
        _entry(
            "dig_dnssec_a", "Ask for A records with signatures requested",
            ["dig", "+dnssec", "+time=2", "+tries=2", "A", name, *server],
            "udp", resolver, "A", 1, "dnssec",
        ),
        _entry(
            "dig_dnssec_cd_a", "Ask again with signature checking disabled",
            ["dig", "+dnssec", "+cd", "+time=2", "+tries=2", "A", name, *server],
            "udp", resolver, "A", 1, "dnssec",
        ),
        _entry(
            "dig_dnssec_ds", "Ask the parent zone whether {0} is signed".format(apex),
            ["dig", "+dnssec", "+time=2", "+tries=2", "DS", apex, *server],
            "udp", resolver, "DS", 1, "dnssec", None, apex,
        ),
        _entry(
            "dig_dnssec_dnskey", "Ask {0} for its signing keys".format(apex),
            ["dig", "+dnssec", "+time=2", "+tries=2", "DNSKEY", apex, *server],
            "udp", resolver, "DNSKEY", 1, "dnssec", None, apex,
        ),
    ]
    # Many ISP and corporate resolvers forward answers without validating them, so
    # they never set the AD flag and the local pair alone can only say "unknown".
    # One extra pair at a resolver that is known to validate turns that into a
    # decidable answer. It reuses the already-disclosed public resolver list, so it
    # is skipped whenever public queries are switched off.
    if validating_address:
        entries.extend((
            _entry(
                "dig_dnssec_validating_a",
                "Ask validating resolver {0} for A records with signatures requested".format(
                    validating_address
                ),
                ["dig", "+dnssec", "+time=2", "+tries=2", "A", name, "@" + validating_address],
                "udp", validating_address, "A", 1, "dnssec",
            ),
            _entry(
                "dig_dnssec_validating_cd_a",
                "Ask validating resolver {0} again with signature checking disabled".format(
                    validating_address
                ),
                ["dig", "+dnssec", "+cd", "+time=2", "+tries=2", "A", name,
                 "@" + validating_address],
                "udp", validating_address, "A", 1, "dnssec",
            ),
        ))
    return entries


def _public_layer_entries(
    name: str, addresses: List[str], record_types: Optional[List[str]] = None
) -> List[dict]:
    record_types = list(record_types or ("A", "AAAA"))
    entries = []
    for address in addresses:
        for qtype in record_types:
            entries.append(_entry(
                "dig_public_{0}_{1}".format(_resolver_slug(address), qtype.lower()),
                "Ask public resolver {0} for {1} records".format(address, qtype),
                ["dig", "+time=2", "+tries=2", qtype, name, "@" + address],
                "udp", address, qtype, 1, "public",
            ))
    return entries


def _trace_layer_entries(name: str, record_types: Optional[List[str]] = None) -> List[dict]:
    entries = []
    for qtype in list(record_types or ("A",)):
        suffix = "" if qtype == "A" else "_" + qtype.lower()
        entries.append(_entry(
            "dig_trace" + suffix, "Follow the delegation from the root servers down",
            ["dig", "+trace", "+time=2", "+tries=2", qtype, name],
            "udp", "root_servers", qtype, 1, "trace", "trace", None, _TRACE_TIMEOUT_S,
        ))
    return entries


def _authoritative_layer_entries(
    name: str,
    servers: List[dict],
    zone: Optional[str] = None,
    record_types: Optional[List[str]] = None,
) -> List[dict]:
    """Direct non-recursive queries against already-observed authoritative addresses."""
    record_types = list(record_types or ("A",))
    entries = []
    for server in servers[:_MAX_AUTHORITATIVE_SERVERS]:
        address = server["address"]
        slug = _resolver_slug(address)
        for qtype in record_types:
            entries.append(_entry(
                "dig_authoritative_{0}_{1}".format(slug, qtype.lower()),
                "Ask authoritative server {0} directly for {1} records".format(
                    server.get("name") or address, qtype,
                ),
                ["dig", "+norecurse", "+time=2", "+tries=2", qtype, name, "@" + address],
                "udp", address, qtype, 1, "authoritative", "authoritative",
            ))
    if entries and zone:
        address = servers[0]["address"]
        entries.append(_entry(
            "dig_authoritative_ns",
            "Ask {0} which nameservers it lists for {1}".format(
                servers[0].get("name") or address, zone
            ),
            ["dig", "+norecurse", "+time=2", "+tries=2", "NS", zone, "@" + address],
            "udp", address, "NS", 1, "authoritative", "child_authority", zone,
        ))
    return entries


def build_probe_plan(target: dict, capabilities: dict, options: Optional[dict] = None) -> List[dict]:
    """Build a deterministic, read-only probe plan without executing it."""
    name = _validated_plan_target(target)
    if not isinstance(capabilities, dict):
        raise ValueError("capabilities must be a mapping")
    if capabilities and not set(capabilities) & set(_CAPABILITIES):
        # An empty mapping means every tool is absent, which is a real case. A non-empty
        # mapping naming no known tool is a mis-passed argument, and returning an empty
        # plan for it would look like "nothing to probe" instead of a wrong call.
        raise ValueError(
            "capabilities must map probe tool names ({0}) to booleans".format(
                ", ".join(_CAPABILITIES)
            )
        )
    resolver_address = _resolver_option(options)
    resolver = resolver_address or "system"
    record_types = _record_types_option(options)
    samples = _samples_option(options)
    layers = _layers_option(options)
    public_addresses = _public_addresses_option(options)
    multi_type = len(record_types) > 1
    plan: List[dict] = []

    for qtype in record_types:
        for sample in range(1, samples + 1):
            if capabilities.get("dig"):
                server = ["@" + resolver_address] if resolver_address else []
                plan.extend((
                    _entry(
                        _planned_id("dig", "udp", qtype, sample, multi_type, samples),
                        "Query {0} records over UDP".format(qtype),
                        ["dig", "+time=2", "+tries=2", qtype, name, *server],
                        "udp", resolver, qtype, sample,
                    ),
                    _entry(
                        _planned_id("dig", "tcp", qtype, sample, multi_type, samples),
                        "Query {0} records over TCP".format(qtype),
                        ["dig", "+time=2", "+tries=2", "+tcp", qtype, name, *server],
                        "tcp", resolver, qtype, sample,
                    ),
                ))
            elif capabilities.get("kdig"):
                server = ["@" + resolver_address] if resolver_address else []
                plan.extend((
                    _entry(
                        _planned_id("kdig", "udp", qtype, sample, multi_type, samples),
                        "Query {0} records over UDP".format(qtype),
                        ["kdig", "+time=2", "+retry=1", qtype, name, *server],
                        "udp", resolver, qtype, sample,
                    ),
                    _entry(
                        _planned_id("kdig", "tcp", qtype, sample, multi_type, samples),
                        "Query {0} records over TCP".format(qtype),
                        ["kdig", "+time=2", "+retry=1", "+tcp", qtype, name, *server],
                        "tcp", resolver, qtype, sample,
                    ),
                ))
            elif capabilities.get("nslookup"):
                server = [resolver_address] if resolver_address else []
                prefix = ["nslookup", "-timeout=2", "-retry=1", "-type=" + qtype]
                plan.extend((
                    _entry(
                        _planned_id("nslookup", "udp", qtype, sample, multi_type, samples),
                        "Query {0} records over UDP".format(qtype),
                        [*prefix, name, *server], "udp", resolver, qtype, sample,
                    ),
                    _entry(
                        _planned_id("nslookup", "tcp", qtype, sample, multi_type, samples),
                        "Query {0} records over TCP".format(qtype),
                        ["nslookup", "-vc", "-timeout=2", "-retry=1", "-type=" + qtype, name, *server],
                        "tcp", resolver, qtype, sample,
                    ),
                ))
            elif capabilities.get("host"):
                server = [resolver_address] if resolver_address else []
                prefix = ["host", "-W", "2", "-R", "1", "-t", qtype]
                plan.extend((
                    _entry(
                        _planned_id("host", "udp", qtype, sample, multi_type, samples),
                        "Query {0} records over UDP".format(qtype),
                        [*prefix, name, *server], "udp", resolver, qtype, sample,
                    ),
                    _entry(
                        _planned_id("host", "tcp", qtype, sample, multi_type, samples),
                        "Query {0} records over TCP".format(qtype),
                        ["host", "-T", "-W", "2", "-R", "1", "-t", qtype, name, *server],
                        "tcp", resolver, qtype, sample,
                    ),
                ))

            if capabilities.get("resolvectl"):
                plan.append(_entry(
                    _planned_id("resolvectl", "local", qtype, sample, multi_type, samples),
                    "Observe local {0} resolver result".format(qtype),
                    ["resolvectl", "query", "--type=" + qtype, name],
                    "local", "system", qtype, sample,
                ))
            if capabilities.get("getent") and qtype in {"A", "AAAA"}:
                database = "ahostsv4" if qtype == "A" else "ahostsv6"
                plan.append(_entry(
                    _planned_id("getent", "local", qtype, sample, multi_type, samples),
                    "Observe local {0} name-service result".format(qtype),
                    ["getent", database, name],
                    "local", "system", qtype, sample,
                ))

    # The extra layers all rely on dig-specific options; other tools use different
    # syntax, so an unavailable dig leaves the layer unplanned and reported as skipped.
    if capabilities.get("dig"):
        if "dnssec" in layers:
            plan.extend(_dnssec_layer_entries(
                name, resolver_address, resolver,
                public_addresses[0] if public_addresses else None,
            ))
        if "public" in layers:
            plan.extend(_public_layer_entries(name, public_addresses, record_types))
        if "trace" in layers:
            plan.extend(_trace_layer_entries(name, record_types))
    return plan


def _bounded_text(value: Any, max_output_bytes: int) -> tuple[str, bool]:
    if value is None:
        return "", False
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    encoded = text.encode("utf-8")
    if len(encoded) <= max_output_bytes:
        return text, False
    return encoded[:max_output_bytes].decode("utf-8", errors="ignore"), True


def _is_probe_target(value: str) -> bool:
    try:
        return not normalize_target(value)["is_url"]
    except ValueError:
        return False


def _is_resolver_argument(value: str, prefixed: bool) -> bool:
    if prefixed:
        if not value.startswith("@"):
            return False
        value = value[1:]
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _matches_query(
    argv: List[str],
    prefix: List[str],
    resolver_prefix: bool,
    resolver_requirement: str = "optional",
) -> bool:
    if argv[:len(prefix)] != prefix:
        return False
    remainder = argv[len(prefix):]
    if not remainder or not _is_probe_target(remainder[0]):
        return False
    with_resolver = len(remainder) == 2 and _is_resolver_argument(remainder[1], resolver_prefix)
    if resolver_requirement == "required":
        return with_resolver
    if resolver_requirement == "forbidden":
        return len(remainder) == 1
    return len(remainder) == 1 or with_resolver


def _validate_probe_argv(argv: List[str]) -> List[str]:
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must be a non-empty list of text items")
    executable = argv[0]
    if executable not in _CAPABILITIES:
        raise ValueError("probe executable is not allowlisted")
    if argv == _VERSION_COMMANDS.get(executable):
        return list(argv)

    allowed = {
        "dig": (
            any(
                _matches_query(argv, ["dig", "+time=2", "+tries=2", record_type], True)
                or _matches_query(
                    argv, ["dig", "+time=2", "+tries=2", "+tcp", record_type], True
                )
                # Signatures requested, and the same query with checking disabled.
                or _matches_query(
                    argv, ["dig", "+dnssec", "+time=2", "+tries=2", record_type], True
                )
                or _matches_query(
                    argv, ["dig", "+dnssec", "+cd", "+time=2", "+tries=2", record_type], True
                )
                # A non-recursive query is only meaningful at a named server.
                or _matches_query(
                    argv, ["dig", "+norecurse", "+time=2", "+tries=2", record_type], True,
                    "required",
                )
                # A trace always starts at the root servers, so no server may be pinned.
                or _matches_query(
                    argv, ["dig", "+trace", "+time=2", "+tries=2", record_type], True,
                    "forbidden",
                )
                for record_type in _AUTOMATIC_RECORD_TYPES
            )
            or (len(argv) == 2 and _is_probe_target(argv[1]))
        ),
        "kdig": (
            any(
                _matches_query(argv, ["kdig", "+time=2", "+retry=1", record_type], True)
                or _matches_query(
                    argv, ["kdig", "+time=2", "+retry=1", "+tcp", record_type], True
                )
                for record_type in _AUTOMATIC_RECORD_TYPES
            )
            or (len(argv) == 2 and _is_probe_target(argv[1]))
        ),
        "nslookup": any(
            _matches_query(
                argv,
                ["nslookup", "-timeout=2", "-retry=1", "-type=" + record_type],
                False,
            )
            or _matches_query(
                argv,
                ["nslookup", "-vc", "-timeout=2", "-retry=1", "-type=" + record_type],
                False,
            )
            for record_type in _AUTOMATIC_RECORD_TYPES
        ) or _matches_query(argv, ["nslookup", "-timeout=2", "-retry=1"], False),
        "host": any(
            _matches_query(
                argv, ["host", "-W", "2", "-R", "1", "-t", record_type], False
            )
            or _matches_query(
                argv, ["host", "-T", "-W", "2", "-R", "1", "-t", record_type], False
            )
            for record_type in _AUTOMATIC_RECORD_TYPES
        ),
        "resolvectl": any(
            _matches_query(argv, ["resolvectl", "query", "--type=" + record_type], False)
            for record_type in _AUTOMATIC_RECORD_TYPES
        ) or _matches_query(argv, ["resolvectl", "query"], False),
        "getent": any(
            _matches_query(argv, ["getent", database], False)
            for database in ("ahosts", "ahostsv4", "ahostsv6")
        ),
        "powershell": False,
    }
    if not allowed[executable]:
        raise ValueError("argv does not match a read-only probe template")
    return list(argv)


def run_probe(
    argv: List[str],
    timeout_s: float = 5.0,
    max_output_bytes: int = 16384,
    runner: Callable = subprocess.run,
) -> dict:
    """Execute one allowlisted read-only probe with bounded captured output."""
    command = _validate_probe_argv(argv)
    if not isinstance(timeout_s, (int, float)) or isinstance(timeout_s, bool) or not math.isfinite(timeout_s) or timeout_s < 0:
        raise ValueError("timeout_s must be a finite non-negative number")
    if not isinstance(max_output_bytes, int) or max_output_bytes < 0:
        raise ValueError("max_output_bytes must be a non-negative integer")

    started_at = _utc_timestamp()
    started = time.monotonic()
    returncode = None
    timed_out = False
    error = None
    stdout_value: Any = ""
    stderr_value: Any = ""
    try:
        completed = runner(
            command,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        returncode = completed.returncode
        stdout_value = completed.stdout
        stderr_value = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout_value = exc.stdout if exc.stdout is not None else exc.output
        stderr_value = exc.stderr
        error = "timeout after {0:g} seconds".format(timeout_s)
    except (FileNotFoundError, OSError) as exc:
        error = "{0}: {1}".format(type(exc).__name__, exc)

    stdout, stdout_truncated = _bounded_text(stdout_value, max_output_bytes)
    stderr, stderr_truncated = _bounded_text(stderr_value, max_output_bytes)
    return {
        "argv": command,
        "started_at": started_at,
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "stdout": stdout,
        "stderr": stderr,
        "parser_status": "not_parsed",
        "error": error,
        "output_truncated": stdout_truncated or stderr_truncated,
    }


def _number_option(options: dict, key: str, default: float, minimum: float) -> float:
    value = options.get(key, default)
    if (not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(value) or value < minimum):
        raise ValueError("{0} must be at least {1}".format(key, minimum))
    return float(value)


def _capabilities_from_options(options: dict) -> dict:
    supplied = options.get("capabilities")
    if supplied is None:
        return detect_capabilities()
    if not isinstance(supplied, dict):
        raise ValueError("capabilities must be a mapping")
    return {name: bool(supplied.get(name, False)) for name in _CAPABILITIES}


def _manual_candidates(
    target: dict,
    resolver: Optional[str],
    capabilities: dict,
    record_types: Optional[List[str]] = None,
) -> List[dict]:
    name = target["hostname"] or target["ip"]
    dig_server = ["@" + resolver] if resolver else []
    plain_server = [resolver] if resolver else []
    requested_types = record_types or ["A"]
    candidates = []
    for qtype in requested_types:
        suffix = "" if len(requested_types) == 1 and qtype == "A" else "_" + qtype.lower()
        candidates.extend((
            _entry(
                "dig_udp" + suffix,
                "Query {0} records over UDP".format(qtype),
                ["dig", "+time=2", "+tries=2", qtype, name, *dig_server],
                "udp", resolver or "system", qtype,
            ),
            _entry(
                "dig_tcp" + suffix,
                "Query {0} records over TCP".format(qtype),
                ["dig", "+time=2", "+tries=2", "+tcp", qtype, name, *dig_server],
                "tcp", resolver or "system", qtype,
            ),
            _entry(
                "kdig_udp" + suffix,
                "Query {0} records over UDP".format(qtype),
                ["kdig", "+time=2", "+retry=1", qtype, name, *dig_server],
                "udp", resolver or "system", qtype,
            ),
            _entry(
                "kdig_tcp" + suffix,
                "Query {0} records over TCP".format(qtype),
                ["kdig", "+time=2", "+retry=1", "+tcp", qtype, name, *dig_server],
                "tcp", resolver or "system", qtype,
            ),
            _entry(
                "nslookup_udp" + suffix,
                "Query {0} records over UDP".format(qtype),
                ["nslookup", "-timeout=2", "-retry=1", "-type=" + qtype, name, *plain_server],
                "udp", resolver or "system", qtype,
            ),
            _entry(
                "host_udp" + suffix,
                "Query {0} records over UDP".format(qtype),
                ["host", "-W", "2", "-R", "1", "-t", qtype, name, *plain_server],
                "udp", resolver or "system", qtype,
            ),
        ))
        candidates.append(_entry(
            "resolvectl" + suffix,
            "Observe local {0} resolver result".format(qtype),
            ["resolvectl", "query", "--type=" + qtype, name],
            "local", "system", qtype,
        ))
        if qtype in {"A", "AAAA"}:
            database = "ahostsv4" if qtype == "A" else "ahostsv6"
            candidates.append(_entry(
                "getent" + suffix,
                "Observe local {0} name-service result".format(qtype),
                ["getent", database, name],
                "local", "system", qtype,
            ))
        if capabilities.get("powershell"):
            command = "Resolve-DnsName -Name '{0}' -Type {1} -DnsOnly".format(name, qtype)
            if resolver:
                command += " -Server '{0}'".format(resolver)
            candidates.append(_entry(
                "powershell_resolve_dnsname" + suffix,
                "User-executed Windows Resolve-DnsName fallback",
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                "udp", resolver or "system", qtype,
            ))
    return candidates


def _dnskey_key_tag(flags: int, protocol: int, algorithm: int, key_base64: str) -> Optional[int]:
    """Compute the DNSKEY key tag (RFC 4034 Appendix B) so DS records can be matched."""
    try:
        key = base64.b64decode(key_base64, validate=True)
    except (ValueError, TypeError):
        return None
    if not key or algorithm == 1:
        # Algorithm 1 (RSAMD5) uses a different rule and is obsolete; report nothing.
        return None
    rdata = struct.pack("!HBB", flags & 0xFFFF, protocol & 0xFF, algorithm & 0xFF) + key
    accumulator = 0
    for index, byte in enumerate(rdata):
        accumulator += byte if index % 2 else byte << 8
    accumulator += (accumulator >> 16) & 0xFFFF
    return accumulator & 0xFFFF


def _parse_ds_record(record: dict) -> Optional[dict]:
    fields = record["data"].split()
    if len(fields) < 4:
        return None
    try:
        return {
            "key_tag": int(fields[0]),
            "algorithm": int(fields[1]),
            "digest_type": int(fields[2]),
        }
    except ValueError:
        return None


def _parse_dnskey_record(record: dict) -> Optional[dict]:
    fields = record["data"].split()
    if len(fields) < 4:
        return None
    try:
        flags, protocol, algorithm = int(fields[0]), int(fields[1]), int(fields[2])
    except ValueError:
        return None
    return {
        "key_tag": _dnskey_key_tag(flags, protocol, algorithm, "".join(fields[3:])),
        "algorithm": algorithm,
        # Bit 0 of the flags field marks a key that signs other keys (the zone's anchor).
        "key_signing_key": bool(flags & 0x0001) and bool(flags & 0x0100),
    }


def _parse_resource_record(line: str) -> Optional[dict]:
    fields = line.split(None, 4)
    if len(fields) != 5:
        return None
    name, ttl_text, record_class, record_type, data = fields
    try:
        ttl = int(ttl_text)
    except ValueError:
        return None
    return {
        "name": name,
        "ttl": ttl,
        "class": record_class.upper(),
        "type": record_type.upper(),
        "data": data.strip(),
    }


def _parse_dig_output(stdout: str, qname: str, qtype: str) -> Optional[dict]:
    header = re.search(r"\bstatus:\s*([A-Z0-9]+)\b", stdout, re.IGNORECASE)
    flags_match = re.search(r"^;;\s*flags:\s*([^;]*);", stdout, re.IGNORECASE | re.MULTILINE)
    flags = flags_match.group(1).lower().split() if flags_match else []
    sections = {"ANSWER": [], "AUTHORITY": [], "ADDITIONAL": []}
    current = None
    parsed_qname = qname
    parsed_qtype = qtype
    edns = None

    for line in stdout.splitlines():
        section_match = re.match(r"^;;\s+(QUESTION|ANSWER|AUTHORITY|ADDITIONAL) SECTION:", line)
        if section_match:
            current = section_match.group(1)
            continue
        if line.startswith(";;") and "SECTION:" not in line:
            current = None
        if line.startswith("; EDNS:"):
            version = re.search(r"version:\s*(\d+)", line)
            udp_size = re.search(r"udp:\s*(\d+)", line)
            edns_flags = re.search(r"flags:\s*([^;]*);", line)
            edns = {
                "enabled": True,
                "version": int(version.group(1)) if version else None,
                "udp_size": int(udp_size.group(1)) if udp_size else None,
                "flags": edns_flags.group(1).lower().split() if edns_flags else [],
            }
            continue
        if current == "QUESTION" and line.startswith(";"):
            question = line[1:].split()
            if len(question) >= 3:
                parsed_qname = question[0].rstrip(".").lower()
                parsed_qtype = question[-1].upper()
            continue
        if current in sections and line and not line.startswith(";"):
            record = _parse_resource_record(line)
            if record is not None:
                sections[current].append(record)

    if header is None and not any(sections.values()):
        return None
    status = header.group(1).upper() if header else None
    answers = sections["ANSWER"]
    addresses = []
    for answer in answers:
        if answer["type"] not in {"A", "AAAA"}:
            continue
        try:
            address = str(ipaddress.ip_address(answer["data"]))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    parsed = {
        "qname": parsed_qname,
        "qtype": parsed_qtype,
        "status": status,
        "rcode": status,
        "flags": flags,
        "tc": "tc" in flags,
        "answers": answers,
        "authority": sections["AUTHORITY"],
        "additional": sections["ADDITIONAL"],
        "addresses": addresses,
    }
    if edns is not None:
        parsed["edns"] = edns
    signature_records = [
        record for record in answers + sections["AUTHORITY"] if record["type"] == "RRSIG"
    ]
    ds_records = [
        entry for entry in (
            _parse_ds_record(record) for record in answers if record["type"] == "DS"
        ) if entry is not None
    ]
    dnskey_records = [
        entry for entry in (
            _parse_dnskey_record(record) for record in answers if record["type"] == "DNSKEY"
        ) if entry is not None
    ]
    signatures_requested = "do" in ((edns or {}).get("flags") or [])
    if signatures_requested or signature_records or ds_records or dnskey_records:
        # Only queries that actually asked for signatures may speak about DNSSEC.
        parsed["dnssec"] = {
            "requested": signatures_requested,
            "ad_flag": "ad" in flags,
            "cd_flag": "cd" in flags,
            "rrsig_present": bool(signature_records),
            "rrsig_count": len(signature_records),
        }
        if ds_records:
            parsed["dnssec"]["ds_records"] = ds_records
        if dnskey_records:
            parsed["dnssec"]["dnskey_records"] = dnskey_records
    nameservers = []
    for record in answers + sections["AUTHORITY"]:
        # An NS set is authoritative in ANSWER and a referral in AUTHORITY; both name servers.
        if record["type"] != "NS":
            continue
        server = record["data"].rstrip(".")
        if server not in nameservers:
            nameservers.append(server)
    if nameservers:
        parsed["nameservers"] = nameservers
    cname_edges = [
        {
            "owner": record["name"].rstrip(".").lower(),
            "target": record["data"].rstrip(".").lower(),
        }
        for record in answers if record["type"] == "CNAME"
    ]
    if cname_edges:
        cname_chain = []
        for edge in cname_edges:
            if not cname_chain:
                cname_chain.extend((edge["owner"], edge["target"]))
            elif cname_chain[-1] == edge["owner"]:
                cname_chain.append(edge["target"])
            else:
                cname_chain.extend((edge["owner"], edge["target"]))
        parsed["cname_edges"] = cname_edges
        parsed["cname_chain"] = cname_chain
    return parsed


_TRACE_RECEIVED = re.compile(
    r"^;;\s*Received\s+\d+\s+bytes\s+from\s+(\S+?)#\d+\(([^)]*)\)\s+in\s+(\d+)\s*ms",
    re.IGNORECASE,
)


def _trace_hop(level: int, records: List[dict], received: "re.Match") -> dict:
    nameservers = [
        record["data"].rstrip(".").lower() for record in records if record["type"] == "NS"
    ]
    glue = {
        record["name"].rstrip(".").lower(): record["data"]
        for record in records if record["type"] in {"A", "AAAA"}
    }
    owners = [record["name"].rstrip(".").lower() for record in records if record["type"] == "NS"]
    answers = [
        record for record in records if record["type"] in {"A", "AAAA", "CNAME"}
    ]
    # Only a referral or the final answer names a zone. A block carrying just NSEC or
    # RRSIG records is the server proving a name does not exist, and its owner name
    # (the neighbouring name in sort order) is not a zone the walk reached.
    if owners:
        zone = owners[0]
    elif answers:
        zone = answers[0]["name"].rstrip(".").lower()
    else:
        zone = None
    hop = {
        "level": level,
        "zone": "." if zone == "" else zone,
        "referral": bool(owners),
        "nameservers": nameservers,
        "from_address": received.group(1),
        "from_server": received.group(2).rstrip(".").lower() or None,
        "rtt_ms": int(received.group(3)),
    }
    if glue:
        hop["glue"] = glue
    if answers:
        hop["answers"] = answers
    return hop


def _parse_dig_trace_output(stdout: str, qname: str, qtype: str) -> Optional[dict]:
    """Turn a delegation walk into ordered hops; the format differs from a normal answer."""
    hops: List[dict] = []
    pending: List[dict] = []
    for line in stdout.splitlines():
        received = _TRACE_RECEIVED.match(line)
        if received is not None:
            hops.append(_trace_hop(len(hops) + 1, pending, received))
            pending = []
            continue
        if not line or line.startswith(";"):
            continue
        record = _parse_resource_record(line)
        if record is not None:
            pending.append(record)
    if not hops:
        return None
    final = hops[-1]
    answers = final.get("answers", [])
    parsed = {
        "qname": qname,
        "qtype": qtype,
        "hops": hops,
        "hop_count": len(hops),
        "delegation_chain": [hop["zone"] for hop in hops if hop["zone"]],
        "answers": answers,
        "nameservers": final["nameservers"],
    }
    if answers:
        # A trace that ends in an answer for the asked name did complete the walk.
        parsed["status"] = "NOERROR"
        parsed["rcode"] = "NOERROR"
    return parsed


def _parse_text_tool_output(executable: str, result: dict, qname: str, qtype: str) -> Optional[dict]:
    text = result["stdout"] + "\n" + result["stderr"]
    upper = text.upper()
    status = None
    for candidate in ("NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR"):
        if candidate in upper:
            status = candidate
            break
    if executable == "host":
        numeric_status = re.search(r"not found:\s*(\d+)", text, re.IGNORECASE)
        if numeric_status:
            status = {"2": "SERVFAIL", "3": "NXDOMAIN", "5": "REFUSED"}.get(
                numeric_status.group(1), status
            )
        if re.search(r"\bhas no\s+{0}\s+record\b".format(re.escape(qtype)), text, re.IGNORECASE):
            status = "NOERROR"
    if executable == "nslookup" and "NO ANSWER" in upper:
        status = "NOERROR"
    if status is None and result.get("returncode") == 0:
        status = "NOERROR"

    candidates = []
    if executable == "nslookup":
        saw_answer_name = False
        for line in text.splitlines():
            if re.match(r"^\s*Name:\s*", line, re.IGNORECASE):
                saw_answer_name = True
                continue
            address_line = re.match(r"^\s*Address(?:es)?:\s*(.*)$", line, re.IGNORECASE)
            if saw_answer_name and address_line:
                candidates.extend(_IP_CANDIDATE.findall(address_line.group(1)))
    elif executable == "host":
        for line in text.splitlines():
            match = re.search(r"\bhas (?:IPv6 )?address\s+(\S+)", line, re.IGNORECASE)
            if match:
                candidates.append(match.group(1))
    elif executable == "getent":
        candidates.extend(
            line.split()[0] for line in text.splitlines() if line.split()
        )
    else:
        for line in text.splitlines():
            if qname.lower() in line.lower():
                candidates.extend(_IP_CANDIDATE.findall(line))

    addresses = []
    for candidate in candidates:
        try:
            address = str(ipaddress.ip_address(candidate.split("#", 1)[0]))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    if status is None and not addresses:
        return None
    answers = [
        {"name": qname + ".", "ttl": None, "class": "IN", "type": qtype, "data": address}
        for address in addresses
        if (qtype == "A" and ipaddress.ip_address(address).version == 4)
        or (qtype == "AAAA" and ipaddress.ip_address(address).version == 6)
    ]
    if executable in {"resolvectl", "getent"} and not answers:
        return None
    return {
        "qname": qname,
        "qtype": qtype,
        "status": status,
        "rcode": status,
        "flags": [],
        "tc": False,
        "answers": answers,
        "authority": [],
        "additional": [],
        "addresses": [answer["data"] for answer in answers],
    }


def _parse_probe_result(entry: dict, result: dict, qname: str, qtype: str = "A") -> dict:
    if result.get("timed_out") or result.get("error"):
        return {"raw_summary": {"stdout": result["stdout"], "stderr": result["stderr"]}}
    executable = entry["argv"][0]
    if executable == "dig" and "+trace" in entry["argv"]:
        parsed = _parse_dig_trace_output(result["stdout"], qname, qtype)
    elif executable in {"dig", "kdig"}:
        parsed = _parse_dig_output(result["stdout"], qname, qtype)
    else:
        parsed = _parse_text_tool_output(executable, result, qname, qtype)
    if parsed is not None:
        result["parser_status"] = "parsed"
        return parsed
    return {"raw_summary": {"stdout": result["stdout"], "stderr": result["stderr"]}}


def _parse_resolv_conf(text: str) -> dict:
    resolver_addresses = []
    search_domains = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if fields[0].lower() == "nameserver" and len(fields) >= 2:
            try:
                address = str(ipaddress.ip_address(fields[1].split("%", 1)[0]))
            except ValueError:
                continue
            if address not in resolver_addresses:
                resolver_addresses.append(address)
        elif fields[0].lower() in {"search", "domain"}:
            for domain in fields[1:]:
                normalized = domain.rstrip(".").lower()
                if normalized and normalized not in search_domains:
                    search_domains.append(normalized)
    return {
        "resolver_addresses": resolver_addresses,
        "search_domains": search_domains,
        "routing_domains": [],
    }


def _reviewed_preflight_commands(platform_name: str) -> dict:
    if platform_name == "Darwin":
        return {
            "resolver": "scutil --dns",
            "interfaces": "ifconfig",
            "network_type": "networksetup -listallhardwareports",
            "proxy_doh": "scutil --proxy",
        }
    if platform_name == "Windows":
        return {
            "resolver": "ipconfig /all",
            "interfaces": "ipconfig /all",
            "network_type": "ipconfig /all",
            "proxy_doh": "netsh winhttp show proxy",
        }
    return {
        "resolver": "resolvectl status",
        "interfaces": "ip -brief link",
        "network_type": "ip route show default",
        "proxy_doh": "resolvectl status",
    }


def _preflight_skip(identifier: str, reason: str, command: str) -> dict:
    return {
        "id": identifier,
        "reason": reason,
        "manual_command": command,
        "execution": "user-executed only after review",
        "resolver": "system",
    }


def _collect_platform_preflight() -> tuple[dict, List[dict]]:
    platform_name = platform.system()
    commands = _reviewed_preflight_commands(platform_name)
    skipped = []
    resolver_configuration = {
        "status": "unavailable",
        "source": None,
        "resolver_addresses": [],
        "search_domains": [],
        "routing_domains": [],
    }
    resolv_conf = Path("/etc/resolv.conf")
    try:
        with resolv_conf.open("rb") as handle:
            raw = handle.read(_PREFLIGHT_FILE_LIMIT_BYTES + 1)
        if len(raw) > _PREFLIGHT_FILE_LIMIT_BYTES:
            raise ValueError("resolver configuration exceeds bounded read limit")
        parsed = _parse_resolv_conf(raw.decode("utf-8", errors="replace"))
        resolver_configuration.update(parsed)
        resolver_configuration.update({"status": "collected", "source": str(resolv_conf)})
        if not parsed["resolver_addresses"]:
            resolver_configuration["status"] = "partial"
            skipped.append(_preflight_skip(
                "preflight_resolver_configuration",
                "actual system resolver addresses were not present in the bounded resolver configuration",
                commands["resolver"],
            ))
    except (OSError, ValueError):
        skipped.append(_preflight_skip(
            "preflight_resolver_configuration",
            "actual system resolver configuration was unavailable to the bounded collector",
            commands["resolver"],
        ))

    try:
        interface_names = [name for _, name in socket.if_nameindex()]
        interfaces = {
            "status": "collected",
            "source": "socket.if_nameindex",
            "names": interface_names,
        }
    except OSError:
        interfaces = {"status": "unavailable", "source": "socket.if_nameindex", "names": []}
        skipped.append(_preflight_skip(
            "preflight_interfaces",
            "interface names were unavailable to the standard-library collector",
            commands["interfaces"],
        ))

    proxy_names = (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    )
    proxy_present = any(name in os.environ for name in proxy_names)
    skipped.extend((
        _preflight_skip(
            "preflight_routing_domains",
            "resolver routing domains are not available from portable standard-library APIs",
            commands["resolver"],
        ),
        _preflight_skip(
            "preflight_network_type",
            "network type is not available from portable standard-library APIs",
            commands["network_type"],
        ),
        _preflight_skip(
            "preflight_proxy_doh",
            "proxy values and application DoH configuration are not collected automatically",
            commands["proxy_doh"],
        ),
    ))
    return {
        "resolver_configuration": resolver_configuration,
        "interfaces": interfaces,
        "network_type": {"status": "unknown"},
        "proxy_doh_hints": {
            "status": "partial" if proxy_present else "unknown",
            "proxy_environment_present": proxy_present,
            "doh": "unknown",
        },
    }, skipped


def _is_internal_name(target: dict) -> bool:
    if target["ip"]:
        address = ipaddress.ip_address(target["ip"])
        # Remote observation is limited to globally routable unicast addresses. The
        # standard-library flags cover private, documentation, loopback, link-local,
        # shared, multicast, reserved, and unspecified ranges together.
        return not address.is_global or address.is_multicast
    hostname = target["hostname"]
    return "." not in hostname or hostname.endswith(_SPECIAL_USE_SUFFIXES)


def _tool_versions(capabilities: dict, runner: Callable, deadline: float, max_output_bytes: int) -> dict:
    versions = {}
    for executable in _CAPABILITIES:
        if not capabilities.get(executable):
            versions[executable] = {"available": False, "version": None}
            continue
        command = _VERSION_COMMANDS.get(executable)
        if command is None:
            versions[executable] = {
                "available": True,
                "version": None,
                "error": "version probe unsupported",
            }
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            versions[executable] = {"available": True, "version": None, "error": "total deadline elapsed"}
            continue
        result = run_probe(
            command,
            timeout_s=min(1.0, remaining),
            max_output_bytes=max_output_bytes,
            runner=runner,
        )
        output_lines = (result["stdout"] or result["stderr"]).splitlines()
        succeeded = (
            result["returncode"] == 0
            and not result["timed_out"]
            and result["error"] is None
            and bool(output_lines)
        )
        first_line = output_lines[0] if succeeded else None
        error = result["error"]
        if error is None and result["returncode"] not in {0, None}:
            error = "version command exited {0}".format(result["returncode"])
        elif error is None and not output_lines:
            error = "version output unavailable"
        versions[executable] = {
            "available": True,
            "version": first_line,
            "error": error,
        }
    return versions


def _skip_entry(entry: dict, reason: str) -> dict:
    record = {
        "id": entry["id"],
        "reason": reason,
        "manual_command": shlex.join(entry["argv"]),
        "resolver": entry["resolver"],
        "qtype": entry["qtype"],
        "sample": entry["sample"],
    }
    if entry.get("layer"):
        record["layer"] = entry["layer"]
    return record


def _budget_reason(entry: dict, deadlines: Dict[str, float], deadline: float) -> str:
    layer = entry.get("layer", "local")
    if deadlines.get(layer, deadline) >= deadline:
        return "total deadline elapsed"
    return "{0} layer time budget elapsed".format(layer)


def _probe_record(entry: dict, result: dict, default_qname: str, resolver_addresses: List[str]) -> dict:
    qname = entry.get("qname") or default_qname
    parsed = _parse_probe_result(entry, result, qname, entry["qtype"])
    protocol_fields = {
        key: value for key, value in parsed.items()
        if key not in {"addresses", "raw_summary"}
    }
    return {
        **entry,
        **result,
        "qname": qname,
        "qtype": entry["qtype"],
        "role": entry.get("role") or ("local" if entry["transport"] == "local" else "recursive"),
        "resolver_addresses": resolver_addresses,
        **protocol_fields,
        "parsed": parsed,
    }


def _entry_resolver_addresses(
    entry: dict, resolver: Optional[str], preflight: dict
) -> List[str]:
    """Which resolver addresses actually answered this probe."""
    address = entry.get("resolver")
    if address and address not in {"system", "root_servers"}:
        return [address]
    if entry.get("layer") == "trace":
        return []
    if resolver:
        return [resolver]
    return list(preflight.get("resolver_configuration", {}).get("resolver_addresses", []))


def _layer_deadlines(layers: List[str], start: float, deadline: float) -> Dict[str, float]:
    """Give every layer its own budget so one slow layer cannot starve the others."""
    if len(layers) <= 1:
        return {layer: deadline for layer in layers}
    return {
        layer: min(deadline, start + _LAYER_BUDGET_S.get(layer, _CLI_TOTAL_TIMEOUT_S))
        for layer in layers
    }

def _run_probe_batch(
    entries: List[dict],
    timeout_s: float,
    deadlines: Dict[str, float],
    fallback_deadline: float,
    max_output_bytes: int,
    runner: Callable,
    semaphores: Dict[str, Any],
    semaphore_lock: Any,
) -> List[Optional[dict]]:
    """Run entries concurrently; return results in plan order, None when out of budget."""
    if not entries:
        return []

    def _semaphore(key: str) -> Any:
        with semaphore_lock:
            return semaphores.setdefault(key, threading.Semaphore(_MAX_PARALLEL_PER_RESOLVER))

    def _one(entry: dict) -> Optional[dict]:
        deadline = deadlines.get(entry.get("layer", "local"), fallback_deadline)
        if deadline - time.monotonic() <= 0:
            return None
        with _semaphore(entry["resolver"]):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            budget = entry.get("timeout_s") or timeout_s
            return run_probe(
                entry["argv"],
                timeout_s=min(budget, remaining),
                max_output_bytes=max_output_bytes,
                runner=runner,
            )

    workers = max(1, min(_MAX_PARALLEL_PROBES, len(entries)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, entry) for entry in entries]
        return [future.result() for future in futures]


def _observed_nameservers(probes: List[dict], default_qname: str) -> dict:
    """Reuse nameserver names and glue already seen instead of asking again."""
    zone = None
    names: List[str] = []
    glue: Dict[str, str] = {}
    for probe in probes:
        for hop in probe.get("hops") or []:
            hop_zone = (hop.get("zone") or "").strip(".")
            if not hop.get("nameservers"):
                continue
            if zone is None or len(hop_zone) > len(zone):
                zone = hop_zone
                names = list(hop["nameservers"])
            for server, address in (hop.get("glue") or {}).items():
                glue.setdefault(server.rstrip(".").lower(), address)
    if not names:
        for probe in probes:
            if probe.get("qtype") == "NS" and probe.get("nameservers"):
                names = list(probe["nameservers"])
                zone = _apex_candidate(probe.get("qname") or default_qname)
                break
    if not names:
        for probe in probes:
            if probe.get("nameservers"):
                names = list(probe["nameservers"])
                zone = _apex_candidate(probe.get("qname") or default_qname)
                break
    for probe in probes:
        for record in probe.get("additional") or []:
            if record.get("type") in {"A", "AAAA"} and record.get("data"):
                glue.setdefault(record["name"].rstrip(".").lower(), record["data"])
    ordered = []
    for name in names:
        cleaned = name.rstrip(".").lower()
        if cleaned and cleaned not in ordered:
            ordered.append(cleaned)
    return {"zone": zone, "nameservers": ordered, "glue": glue}


def _authoritative_layer(
    default_qname: str,
    probes: List[dict],
    resolver: Optional[str],
    preflight: dict,
    timeout_s: float,
    deadlines: Dict[str, float],
    deadline: float,
    max_output_bytes: int,
    runner: Callable,
    semaphores: Dict[str, Any],
    semaphore_lock: Any,
    record_types: Optional[List[str]] = None,
) -> dict:
    """Resolve nameserver addresses when needed, then plan direct authoritative queries."""
    discovery = _observed_nameservers(probes, default_qname)
    candidates = discovery["nameservers"][:_MAX_AUTHORITATIVE_SERVERS]
    if not candidates:
        return {"probes": [], "plan": [], "skipped": [{
            "id": "dig_authoritative",
            "reason": "no nameserver names were observed, so no authoritative server could be asked",
            "manual_command": shlex.join(
                ["dig", "+time=2", "+tries=2", "NS", _apex_candidate(default_qname)]
            ),
            "resolver": resolver or "system",
            "qtype": "NS",
            "layer": "authoritative",
        }]}

    servers = []
    resolve_plan = []
    for name in candidates:
        address = discovery["glue"].get(name)
        if address:
            servers.append({"name": name, "address": address})
        elif _is_probe_target(name):
            resolve_plan.append(_entry(
                "dig_authoritative_resolve_{0}".format(_resolver_slug(name)),
                "Look up the address of nameserver {0}".format(name),
                ["dig", "+time=2", "+tries=2", "A", name]
                + (["@" + resolver] if resolver else []),
                "udp", resolver or "system", "A", 1, "authoritative", "recursive", name,
            ))

    resolved_probes = []
    skipped = []
    if resolve_plan:
        results = _run_probe_batch(
            resolve_plan, timeout_s, deadlines, deadline, max_output_bytes, runner,
            semaphores, semaphore_lock,
        )
        for entry, result in zip(resolve_plan, results):
            if result is None:
                skipped.append(_skip_entry(entry, _budget_reason(entry, deadlines, deadline)))
                continue
            record = _probe_record(
                entry, result, default_qname,
                _entry_resolver_addresses(entry, resolver, preflight),
            )
            resolved_probes.append(record)
            addresses = (record.get("parsed") or {}).get("addresses") or []
            if addresses:
                servers.append({"name": entry["qname"], "address": addresses[0]})

    ordered = []
    for name in candidates:
        for server in servers:
            if server["name"] == name and server not in ordered:
                ordered.append(server)
    if not ordered:
        skipped.append({
            "id": "dig_authoritative",
            "reason": "no nameserver address could be determined from the collected evidence",
            "manual_command": shlex.join(["dig", "+time=2", "+tries=2", "A", candidates[0]]),
            "resolver": resolver or "system",
            "qtype": "A",
            "layer": "authoritative",
        })
    return {
        "probes": resolved_probes,
        "plan": _authoritative_layer_entries(
            default_qname, ordered, discovery["zone"], record_types,
        ),
        "skipped": skipped,
    }


def _dnssec_assessment(probes: List[dict]) -> Optional[dict]:
    """Decide signed / unsigned / broken / undecided from the four DNSSEC probes."""
    layer = [probe for probe in probes if probe.get("layer") == "dnssec"]
    if not layer:
        return None
    by_id = {probe["id"]: probe for probe in layer}
    signed = by_id.get("dig_dnssec_a") or {}
    unchecked = by_id.get("dig_dnssec_cd_a") or {}
    parent = by_id.get("dig_dnssec_ds") or {}
    keys = by_id.get("dig_dnssec_dnskey") or {}
    checker = by_id.get("dig_dnssec_validating_a") or {}
    checker_unchecked = by_id.get("dig_dnssec_validating_cd_a") or {}
    ds_records = (parent.get("dnssec") or {}).get("ds_records") or []
    dnskey_records = (keys.get("dnssec") or {}).get("dnskey_records") or []
    ad_flag = bool((signed.get("dnssec") or {}).get("ad_flag"))
    checker_ad_flag = bool((checker.get("dnssec") or {}).get("ad_flag"))
    signed_status = signed.get("status")
    unchecked_status = unchecked.get("status")
    checker_status = checker.get("status")
    checker_unchecked_status = checker_unchecked.get("status")
    checker_address = checker.get("resolver")
    ds_status = parent.get("status")
    ds_tags = sorted({item["key_tag"] for item in ds_records if item.get("key_tag")})
    key_tags = sorted({item["key_tag"] for item in dnskey_records if item.get("key_tag")})
    matched = sorted(set(ds_tags) & set(key_tags))
    # A resolver that answers SERVFAIL only while checking is on has itself rejected
    # the signatures. Either resolver showing that pattern is enough to call it broken.
    local_rejects = signed_status == "SERVFAIL" and unchecked_status == "NOERROR"
    checker_rejects = checker_status == "SERVFAIL" and checker_unchecked_status == "NOERROR"

    if local_rejects or checker_rejects:
        validation = "bogus"
        reason = "开启签名校验时查询失败，关闭校验后立刻成功，说明这个域名的签名校验没有通过"
        if checker_rejects and not local_rejects:
            reason += "（由会做校验的公共解析器 {0} 判定）".format(checker_address)
    elif ds_status == "NOERROR" and not ds_records:
        validation = "insecure"
        reason = "上级域没有为它登记签名指纹（DS 记录），说明这个域名没有启用 DNSSEC"
    elif ds_records and ad_flag and signed_status == "NOERROR":
        validation = "secure"
        reason = "上级域登记了签名指纹，解析器也把这次答案标记为已通过校验"
    elif ds_records and checker_ad_flag and checker_status == "NOERROR":
        validation = "secure"
        reason = (
            "上级域登记了签名指纹，会做校验的公共解析器 {0} 把答案标记为已通过校验"
            "（这台机器当前用的解析器不做校验，所以本机看不到这个标记）".format(checker_address)
        )
    elif ds_records and not ad_flag:
        validation = "indeterminate"
        reason = (
            "上级域登记了签名指纹，但解析器没有把答案标记为已校验："
            "可能是解析器本身不做校验，也可能校验结果在中途被去掉"
        )
    else:
        validation = "indeterminate"
        reason = "证据不足以判断：查询上级域的签名指纹没有成功返回"

    assessment = {
        "validation": validation,
        "reason": reason,
        "apex": parent.get("qname") or keys.get("qname"),
        "ds_present": bool(ds_records),
        "ds_status": ds_status,
        "ds_key_tags": ds_tags,
        "dnskey_key_tags": key_tags,
        "matched_key_tags": matched,
        "ad_flag": ad_flag,
        "signed_query_status": signed_status,
        "checking_disabled_status": unchecked_status,
        "validating_resolver": checker_address,
        "validating_ad_flag": checker_ad_flag,
        "validating_query_status": checker_status,
        "validating_checking_disabled_status": checker_unchecked_status,
        "rrsig_present": bool((signed.get("dnssec") or {}).get("rrsig_present")),
        "supporting_probe_ids": [probe["id"] for probe in layer],
    }
    for probe in layer:
        if isinstance(probe.get("dnssec"), dict):
            probe["dnssec"]["validation"] = validation
    return assessment


def normalize_regions(value: Any) -> List[str]:
    """Uppercase ISO country codes, order preserved, duplicates dropped."""
    if value is None or value == "":
        return []
    items = value.split(",") if isinstance(value, str) else list(value)
    regions: List[str] = []
    for item in items:
        code = str(item).strip()
        if not code:
            continue
        if not _REGION_CODE.match(code):
            raise ValueError(
                "region must be a two-letter country code, got {0!r}".format(code)
            )
        code = code.upper()
        if code not in regions:
            regions.append(code)
    if len(regions) > _REMOTE_MAX_REGIONS:
        raise ValueError(
            "at most {0} regions may be requested".format(_REMOTE_MAX_REGIONS)
        )
    return regions


def remote_measurement_request(name: str, record_type: str, regions: List[str]) -> dict:
    """The exact body that leaves this machine: one name, one record type, no more."""
    if not regions:
        raise ValueError("at least one region is required")
    if record_type not in _REMOTE_RECORD_TYPES:
        raise ValueError("record type {0} is not offered remotely".format(record_type))
    if not _is_probe_target(name):
        raise ValueError("remote target must be a plain hostname")
    return {
        "type": "dns",
        "target": name,
        # Two probes per country: one answer cannot show whether that country's result
        # is stable, and the analyzer will not compare a single sample.
        "locations": [
            {"country": code, "limit": _REMOTE_PROBES_PER_REGION} for code in regions
        ],
        "measurementOptions": {
            "query": {"type": record_type},
            # Remote probes default to their own local resolver, which would make every
            # country incomparable with the others. Pinning one resolver is what makes
            # "the same question, asked from elsewhere" true.
            "resolver": _REMOTE_RESOLVER,
            "protocol": "UDP",
        },
    }


def _remote_status(result: dict) -> Optional[str]:
    for key in ("statusCodeName", "status", "rcode"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    return None


def _remote_answers(result: dict) -> Optional[List[dict]]:
    answers = result.get("answers")
    if not isinstance(answers, list):
        return None
    records = []
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        record = {
            "name": str(answer.get("name", "")).strip(),
            "type": str(answer.get("type", "")).strip().upper(),
            "value": str(answer.get("value", "")).strip(),
        }
        ttl = answer.get("ttl")
        if isinstance(ttl, (int, float)):
            record["ttl"] = int(ttl)
        records.append(record)
    return records


def _remote_skip(reason: str, identifier: str = "remote_observation") -> dict:
    return {
        "id": identifier,
        "reason": reason,
        "resolver": _REMOTE_RESOLVER,
        "qtype": None,
    }


def parse_remote_measurement(document: Any, name: str, record_type: str) -> dict:
    """Turn one remote measurement document into observations, or say why it yielded none."""
    if not isinstance(document, dict):
        return {"observations": [], "skipped": [_remote_skip("response was not an object")]}
    results = document.get("results")
    if not isinstance(results, list) or not results:
        return {
            "observations": [],
            "skipped": [_remote_skip("response carried no probe results")],
        }
    observations: List[dict] = []
    skipped: List[dict] = []
    counters: Dict[str, int] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        probe = item.get("probe") if isinstance(item.get("probe"), dict) else {}
        outcome = item.get("result") if isinstance(item.get("result"), dict) else {}
        country = str(probe.get("country", "")).strip().upper() or "UNKNOWN"
        counters[country] = counters.get(country, 0) + 1
        status = _remote_status(outcome)
        answers = _remote_answers(outcome)
        if status is None and answers is None:
            skipped.append(_remote_skip(
                "a probe in {0} returned neither a status nor answers".format(country),
                "remote_observation_{0}_{1}".format(country.lower(), counters[country]),
            ))
            continue
        observation = {
            "id": "remote_{0}_{1}".format(country.lower(), counters[country]),
            "layer": "regional",
            "role": "recursive",
            # The country code is the viewpoint label the analyzer groups and compares by.
            "vantage": country,
            "resolver": _REMOTE_RESOLVER,
            "transport": "udp",
            "qname": name,
            "qtype": record_type,
            "source": "remote_observation",
            "observed_at": _utc_timestamp(),
            "probe_location": {
                "country": country,
                "city": str(probe.get("city", "")).strip() or None,
                "network": str(probe.get("network", "")).strip() or None,
            },
        }
        if status is not None:
            observation["status"] = status
        if answers is not None:
            observation["answers"] = answers
        observations.append(observation)
    if not observations and not skipped:
        skipped.append(_remote_skip("no probe result could be read"))
    return {"observations": observations, "skipped": skipped}


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect could send the queried name to a host this skill never disclosed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise urllib.error.HTTPError(
            req.full_url, code, "redirects are not followed", headers, fp
        )


def _remote_https_json(method: str, url: str, payload: Optional[dict] = None) -> Any:
    """One HTTPS request to the single disclosed host. No credentials, no redirects."""
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != _REMOTE_API_HOST:
        raise ValueError("remote requests are limited to https://{0}".format(_REMOTE_API_HOST))
    data = None
    headers = {"Accept": "application/json", "User-Agent": "tom-dns-debug"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirects)
    with opener.open(request, timeout=_REMOTE_REQUEST_TIMEOUT_S) as response:
        body = response.read(_REMOTE_MAX_RESPONSE_BYTES + 1)
    if len(body) > _REMOTE_MAX_RESPONSE_BYTES:
        raise ValueError("remote response exceeded the size limit")
    return json.loads(body.decode("utf-8", "replace"))


def fetch_remote_observations(
    target: dict,
    record_type: str,
    regions: List[str],
    acknowledged: bool,
    requester: Callable = _remote_https_json,
    sleeper: Callable = time.sleep,
    clock: Callable = time.monotonic,
) -> dict:
    """Ask remote probes the same question, but only under both explicit opt-ins.

    Only the queried name and record type leave this machine. Nothing collected
    locally — command output, resolver addresses, search domains — is ever sent.
    """
    if not regions:
        return {"observations": [], "skipped": [], "disclosure": None}
    name = target.get("hostname") or target.get("ip")
    if not acknowledged:
        return _remote_refusal(
            regions, name,
            "remote observation requires --acknowledge-remote-query",
            code="not_acknowledged",
        )
    if target.get("ip"):
        return _remote_refusal(
            regions, name,
            "remote observation accepts public hostnames only, not IP literals",
            code="unsuitable_target",
        )
    if _is_internal_name(target):
        # Irreversible once sent: an internal name in a third party's logs cannot be
        # recalled, so the acknowledgement does not unlock this case.
        return _remote_refusal(
            regions, name,
            "internal or private names are never sent to a remote service",
            code="internal_name",
        )
    if not isinstance(name, str) or not _is_probe_target(name):
        return _remote_refusal(
            regions, name, "target is not a plain hostname suitable for remote query",
            code="unsuitable_target",
        )
    try:
        body = remote_measurement_request(name, record_type, regions)
    except ValueError as exc:
        return _remote_refusal(regions, name, str(exc), code="unsuitable_target")

    started = clock()
    try:
        created = requester("POST", _REMOTE_MEASUREMENT_URL, body)
        identifier = created.get("id") if isinstance(created, dict) else None
        if not isinstance(identifier, str) or not identifier.strip():
            raise ValueError("remote service did not return a measurement id")
        url = "{0}/{1}".format(_REMOTE_MEASUREMENT_URL, urllib.parse.quote(identifier, safe=""))
        document = None
        while True:
            document = requester("GET", url)
            status = document.get("status") if isinstance(document, dict) else None
            if status != "in-progress":
                break
            if clock() - started >= _REMOTE_TOTAL_BUDGET_S:
                raise TimeoutError("remote measurement did not finish within the budget")
            sleeper(_REMOTE_POLL_INTERVAL_S)
    except Exception as exc:  # network, protocol, or timeout: the layer is skipped
        return _remote_refusal(
            regions, name, "remote observation failed: {0}".format(type(exc).__name__),
            disclosed=True, code="measurement_failed",
        )
    parsed = parse_remote_measurement(document, name, record_type)
    parsed["disclosure"] = _remote_disclosure(regions, name, record_type, True)
    return parsed


def _remote_refusal(
    regions: List[str],
    name: Any,
    reason: str,
    disclosed: bool = False,
    code: Optional[str] = None,
) -> dict:
    return {
        "observations": [],
        "skipped": [_remote_skip(reason)],
        "disclosure": _remote_disclosure(regions, name, None, disclosed, reason, code),
    }


def _remote_disclosure(
    regions: List[str],
    name: Any,
    record_type: Optional[str],
    disclosed: bool,
    reason: Optional[str] = None,
    code: Optional[str] = None,
) -> dict:
    entry = {
        "id": "remote_query_disclosure",
        "status": "warning" if disclosed else "not_applicable",
        "sent": disclosed,
        "endpoint": _REMOTE_API_HOST if disclosed else None,
        "regions": list(regions),
        "sent_fields": ["queried name", "record type"] if disclosed else [],
        "message": (
            "The queried name {0} and its record type were sent to {1} to obtain "
            "observations from {2}. Nothing else left this machine."
        ).format(name, _REMOTE_API_HOST, ", ".join(regions)) if disclosed else (
            "No name left this machine: {0}.".format(reason or "remote observation not requested")
        ),
    }
    if record_type:
        entry["record_type"] = record_type
    if code:
        # A stable code so a reader or the report never has to parse the sentence.
        entry["reason_code"] = code
    return entry


def collect_evidence(
    raw_target: str,
    options: Optional[dict] = None,
    runner: Callable = subprocess.run,
    remote_fetcher: Callable = fetch_remote_observations,
) -> dict:
    """Run a deterministic probe plan and return a local, versioned evidence record."""

    collected_at = _utc_timestamp()
    if options is None:
        settings: dict = {}
    elif isinstance(options, dict):
        settings = dict(options)
    else:
        raise ValueError("options must be a mapping")

    target = normalize_target(raw_target)
    region = settings.get("region")
    if region is not None and not isinstance(region, str):
        raise ValueError("region must be text")
    timeout_s = _number_option(settings, "timeout_s", 5.0, 0.0)
    deadline_s = _number_option(settings, "deadline_s", 20.0, 0.0)
    record_types = _record_types_option(settings)
    samples = _samples_option(settings)
    max_output_bytes = settings.get("max_output_bytes", 16384)
    if not isinstance(max_output_bytes, int) or max_output_bytes < 0:
        raise ValueError("max_output_bytes must be a non-negative integer")

    capabilities = _capabilities_from_options(settings)
    resolver = _resolver_option(settings)
    layers = _layers_option(settings)
    regions = normalize_regions(settings.get("regions"))
    public_addresses = _public_addresses_option(settings)
    preflight, preflight_skips = _collect_platform_preflight()
    plan_options = {
        "record_types": record_types,
        "samples": samples,
        "layers": layers,
        "public_resolvers": public_addresses,
    }
    if resolver:
        plan_options["resolver"] = resolver
    plan = build_probe_plan(target, capabilities, plan_options)
    start = time.monotonic()
    deadline = start + deadline_s
    deadlines = _layer_deadlines(layers, start, deadline)
    probes = []
    skipped = list(preflight_skips)
    manual_candidates = _manual_candidates(target, resolver, capabilities, record_types)
    planned_ids = {entry["id"] for entry in plan}
    planned_argv = {tuple(entry["argv"]) for entry in plan}
    default_qname = target["hostname"] or target["ip"]
    semaphores: Dict[str, Any] = {}
    semaphore_lock = threading.Lock()

    results = _run_probe_batch(
        plan, timeout_s, deadlines, deadline, max_output_bytes, runner,
        semaphores, semaphore_lock,
    )
    for entry, result in zip(plan, results):
        if result is None:
            skipped.append(_skip_entry(entry, _budget_reason(entry, deadlines, deadline)))
            continue
        probes.append(_probe_record(
            entry, result, default_qname,
            _entry_resolver_addresses(entry, resolver, preflight),
        ))

    if "authoritative" in layers:
        authoritative = _authoritative_layer(
            default_qname, probes, resolver, preflight, timeout_s, deadlines,
            deadline, max_output_bytes, runner, semaphores, semaphore_lock,
            record_types,
        )
        probes.extend(authoritative["probes"])
        skipped.extend(authoritative["skipped"])
        authoritative_plan = authoritative["plan"]
        results = _run_probe_batch(
            authoritative_plan, timeout_s, deadlines, deadline, max_output_bytes,
            runner, semaphores, semaphore_lock,
        )
        for entry, result in zip(authoritative_plan, results):
            if result is None:
                skipped.append(_skip_entry(entry, _budget_reason(entry, deadlines, deadline)))
                continue
            probes.append(_probe_record(
                entry, result, default_qname,
                _entry_resolver_addresses(entry, resolver, preflight),
            ))
        plan = plan + authoritative["probes"] + authoritative_plan
        planned_ids = {entry["id"] for entry in plan}
        planned_argv = {tuple(entry["argv"]) for entry in plan}

    dnssec = _dnssec_assessment(probes)
    remote = {
        "observations": [],
        "skipped": [],
        # Stated even when no region was asked for, so a reader never has to infer from
        # the absence of an entry that nothing was sent.
        "disclosure": _remote_disclosure([], None, None, False),
    }
    if regions:
        remote = remote_fetcher(
            target,
            record_types[0],
            regions,
            bool(settings.get("acknowledge_remote_query")),
        )
        skipped.extend(remote.get("skipped") or [])
    resolvers = []
    for entry in plan:
        if entry["resolver"] not in resolvers:
            resolvers.append(entry["resolver"])

    for entry in manual_candidates:
        if entry["id"] in planned_ids or tuple(entry["argv"]) in planned_argv:
            continue
        executable = entry["argv"][0]
        if executable == "powershell":
            reason = "PowerShell DNS query is user-executed only after review"
            manual_command = entry["argv"][-1]
        elif not capabilities.get(executable):
            reason = "{0} is unavailable".format(executable)
            manual_command = shlex.join(entry["argv"])
        else:
            reason = "{0} was not selected by the deterministic probe plan".format(executable)
            manual_command = shlex.join(entry["argv"])
        skipped.append({
            "id": entry["id"],
            "reason": reason,
            "manual_command": manual_command,
            "resolver": entry["resolver"],
            "qtype": entry["qtype"],
        })

    safety = [{
        "id": "public_query_safety",
        "status": "notice",
        "message": "DNS queries can disclose target names to configured resolvers.",
    }]
    if _is_internal_name(target):
        safety.append({
            "id": "internal_name_exposure",
            "status": "warning",
            "message": "The target appears internal; querying a public resolver can disclose it.",
        })
    else:
        safety.append({
            "id": "internal_name_exposure",
            "status": "not_applicable",
            "message": "The target does not appear to be an internal name or address.",
        })
    if remote.get("disclosure"):
        # Always recorded, in both directions: the reader must be able to see whether
        # anything left this machine without having to reason about the flags used.
        safety.append(remote["disclosure"])

    evidence = {
        "schema_version": _SCHEMA_VERSION,
        "collected_at": collected_at,
        "target": target,
        "environment": {
            "os": platform.platform(),
            "python_version": sys.version.split()[0],
            "timezone": list(time.tzname),
            "region": region,
            "capabilities": capabilities,
            "tool_versions": _tool_versions(capabilities, runner, deadline, max_output_bytes),
            "preflight": preflight,
        },
        "probes": probes,
        "skipped": skipped,
        "resolvers": resolvers,
        "collection_scope": {
            "profile": settings.get("profile", "record"),
            "record_types": record_types,
            "samples": samples,
            "layers": layers,
            "concurrency": {
                "max_parallel_probes": _MAX_PARALLEL_PROBES,
                "max_parallel_per_resolver": _MAX_PARALLEL_PER_RESOLVER,
                "note": (
                    "Probes run concurrently, so started_at values overlap; "
                    "read each duration_ms on its own and never sum them."
                ),
            },
        },
        "analysis_scope": {
            "regional": bool(region) or bool(remote.get("observations")),
            "layers": layers + (["regional"] if remote.get("observations") else []),
            "regions": regions,
        },
        "safety": safety,
        "redaction": {"status": "pending"},
        "findings": [],
    }
    if remote.get("observations"):
        evidence["remote_observations"] = remote["observations"]
    if dnssec:
        evidence["dnssec"] = dnssec
    return evidence


def _redact_url_suffix(text: str) -> str:
    before_fragment, fragment_separator, _ = text.partition("#")
    base, query_separator, _ = before_fragment.partition("?")
    return base + ("?[REDACTED]" if query_separator else "") + (
        "#[REDACTED]" if fragment_separator else ""
    )


def _sanitize_url_match(match: re.Match) -> str:
    text = match.group(0)
    try:
        parsed = urlsplit(text)
    except ValueError:
        return _redact_url_suffix(text)
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((
        parsed.scheme,
        netloc,
        parsed.path,
        "[REDACTED]" if parsed.query else "",
        "[REDACTED]" if parsed.fragment else "",
    ))


def _sanitize_text(text: str) -> str:
    text = _URL_SUBSTRING.sub(_sanitize_url_match, text)
    return _SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + "=[REDACTED]", text)


def _is_secret_marker(value: Any) -> bool:
    return isinstance(value, str) and bool(_SECRET_NAME.fullmatch(value.lstrip("-")))


def _sanitize_evidence(value: Any, sensitive: bool = False) -> Any:
    if sensitive:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            key: _sanitize_evidence(item, bool(_SECRET_NAME.search(str(key))))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        sanitized = []
        redact_next = False
        for item in value:
            if redact_next:
                sanitized.append("[REDACTED]")
                redact_next = False
                continue
            sanitized.append(_sanitize_evidence(item))
            redact_next = _is_secret_marker(item)
        return sanitized
    if isinstance(value, str):
        return _sanitize_text(value)
    return value


def _redacted_argv(argv: Any) -> List[str]:
    if not isinstance(argv, list):
        return []
    return _sanitize_evidence(argv)


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("bundle path must not be a symlink: {0}".format(path))


def write_bundle(evidence: dict, output_dir: Path) -> dict:
    """Write a JSON evidence record and concise local inspection artifacts."""
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be a mapping")
    destination = Path(output_dir)
    _reject_symlink(destination)
    destination.mkdir(parents=True, exist_ok=True)
    raw_directory = destination / "raw"
    _reject_symlink(raw_directory)
    raw_directory.mkdir(exist_ok=True)

    json_path = destination / "dns-debug-report.json"
    # The readable Chinese report owns dns-debug-report.md; the collector only records
    # which commands ran, under its own name, so a finalize pass cannot overwrite it.
    summary_markdown_path = destination / "collection-summary.md"
    commands_path = destination / "commands.json"
    raw_summary_path = raw_directory / "summary.json"
    for path in (json_path, summary_markdown_path, commands_path, raw_summary_path):
        _reject_symlink(path)

    sanitized_evidence = _sanitize_evidence(evidence)
    sanitized_evidence["redaction"] = {"status": "applied"}
    json_path.write_text(json.dumps(sanitized_evidence, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    commands = [
        {"id": item.get("id"), "argv": _redacted_argv(item.get("argv"))}
        for item in sanitized_evidence.get("probes", []) if isinstance(item, dict)
    ]
    commands_path.write_text(json.dumps(commands, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raw_summary = {
        "schema_version": sanitized_evidence.get("schema_version"),
        "probes": [
            {
                "id": item.get("id"),
                "stdout": item.get("stdout", ""),
                "stderr": item.get("stderr", ""),
                "parser_status": item.get("parser_status"),
                "error": item.get("error"),
                "output_truncated": item.get("output_truncated", False),
            }
            for item in sanitized_evidence.get("probes", []) if isinstance(item, dict)
        ],
    }
    raw_summary_path.write_text(json.dumps(raw_summary, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# DNS Collection Summary",
        "",
        "Schema version: {0}".format(sanitized_evidence.get("schema_version", "unknown")),
        "Evidence JSON: dns-debug-report.json",
        "Readable report: dns-debug-report.md (written by dns_analyze.py)",
        "",
        "## Probes",
    ]
    probes = sanitized_evidence.get("probes", [])
    if probes:
        for item in probes:
            if item.get("timed_out"):
                status = "timeout"
            elif item.get("error"):
                status = "execution-error"
            elif item.get("returncode") not in {0, None}:
                status = "failed-exit"
            else:
                status = "completed"
            lines.append("- {0}: {1}".format(item.get("id", "unknown"), status))
    else:
        lines.append("- No probes were run.")
    summary_markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "json": str(json_path),
        "markdown": str(summary_markdown_path),
        "commands": str(commands_path),
        "raw_summary": str(raw_summary_path),
    }


def _cli_resolver(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("resolver must be an IP literal") from exc


def _cli_record_type(value: str) -> str:
    record_type = value.upper()
    if record_type not in _AUTOMATIC_RECORD_TYPES:
        raise argparse.ArgumentTypeError(
            "record type must be one of: {0}".format(", ".join(_AUTOMATIC_RECORD_TYPES))
        )
    return record_type


def _cli_samples(value: str) -> int:
    try:
        samples = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("samples must be an integer") from exc
    if not 1 <= samples <= _CLI_MAX_SAMPLES:
        raise argparse.ArgumentTypeError(
            "samples must be from 1 to {0}".format(_CLI_MAX_SAMPLES)
        )
    return samples


def _cli_timeout(value: str) -> float:
    try:
        timeout_s = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout_s) or timeout_s <= 0 or timeout_s > _CLI_MAX_TIMEOUT_S:
        raise argparse.ArgumentTypeError(
            "timeout must be greater than 0 and at most {0:g} seconds".format(
                _CLI_MAX_TIMEOUT_S
            )
        )
    return timeout_s


def _validate_cli_output_dir(output_dir: Path) -> None:
    _reject_symlink(output_dir)
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError("output directory path exists and is not a directory")
    raw_directory = output_dir / "raw"
    if raw_directory.exists() and not raw_directory.is_dir():
        raise ValueError("output raw path exists and is not a directory")
    _reject_symlink(raw_directory)
    for relative in (
        "dns-debug-report.json",
        "dns-debug-report.md",
        "collection-summary.md",
        "commands.json",
        "raw/summary.json",
    ):
        _reject_symlink(output_dir / relative)


def _prefixed_entries(entries: List[dict], prefix: str) -> List[dict]:
    prefixed = []
    for entry in entries:
        item = dict(entry)
        item["id"] = prefix + str(item.get("id", "unknown"))
        prefixed.append(item)
    return prefixed


def _prefixed_ids(values: Any, prefix: str) -> Any:
    if not isinstance(values, list):
        return values
    return [prefix + str(value) for value in values]


def _collect_cli_evidence(
    target: str,
    resolvers: List[str],
    record_types: List[str],
    samples: int,
    profile: str,
    region: Optional[str],
    timeout_s: float,
    no_public_resolvers: bool,
    internal_public_query_acknowledged: bool,
    layers: Optional[List[str]] = None,
    regions: Optional[List[str]] = None,
    acknowledge_remote_query: bool = False,
) -> dict:
    capabilities = detect_capabilities()
    requested_resolvers: List[Optional[str]] = list(resolvers) or [None]
    layers = _layers_option({"layers": layers} if layers else None)
    extra_layers = [layer for layer in layers if layer != "local"]
    total_timeout_s = _BASELINE_TOTAL_TIMEOUT_S if extra_layers else _CLI_TOTAL_TIMEOUT_S
    deadline = time.monotonic() + total_timeout_s
    combined = None
    multiple = len(requested_resolvers) > 1

    for index, resolver in enumerate(requested_resolvers, start=1):
        options = {
            "capabilities": capabilities,
            "region": region,
            "timeout_s": timeout_s,
            "deadline_s": max(0.0, deadline - time.monotonic()),
            "record_types": record_types,
            "samples": samples,
            "profile": profile,
            "layers": layers,
            "public_resolvers": [] if no_public_resolvers else list(_PUBLIC_RESOLVERS),
        }
        if resolver is not None:
            options["resolver"] = resolver
        if index == 1 and regions:
            # One measurement per run, not one per resolver: the remote question does not
            # change with the local resolver, and each extra call is another disclosure.
            options["regions"] = list(regions)
            options["acknowledge_remote_query"] = acknowledge_remote_query
        evidence = collect_evidence(target, options)
        prefix = "resolver-{0}-".format(index) if multiple else ""
        evidence["probes"] = _prefixed_entries(evidence["probes"], prefix)
        evidence["skipped"] = _prefixed_entries(evidence["skipped"], prefix)
        if isinstance(evidence.get("dnssec"), dict):
            evidence["dnssec"] = dict(evidence["dnssec"])
            evidence["dnssec"]["supporting_probe_ids"] = _prefixed_ids(
                evidence["dnssec"].get("supporting_probe_ids"), prefix,
            )
            evidence["dnssec"]["contradictory_probe_ids"] = _prefixed_ids(
                evidence["dnssec"].get("contradictory_probe_ids"), prefix,
            )
        if combined is None:
            combined = evidence
        else:
            combined["probes"].extend(evidence["probes"])
            combined["skipped"].extend(evidence["skipped"])

    if combined is None:
        raise RuntimeError("no resolver collection was attempted")
    combined["record_type"] = record_types[0] if len(record_types) == 1 else None
    combined["record_types"] = list(record_types)
    combined["resolvers"] = list(resolvers) or ["system"]
    combined["collection"] = {
        "per_command_timeout_s": timeout_s,
        "total_timeout_s": total_timeout_s,
        "profile": profile,
        "record_types": list(record_types),
        "samples": samples,
        "layers": list(layers),
        "public_resolvers_excluded": no_public_resolvers,
        "internal_public_query_acknowledged": internal_public_query_acknowledged,
        "regions": list(regions or []),
        "remote_query_acknowledged": acknowledge_remote_query,
    }
    return combined


def _probe_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect bounded, read-only DNS evidence into a local bundle."
    )
    parser.add_argument("--target", required=True, help="hostname, IP literal, or URL hostname")
    parser.add_argument("--output-dir", required=True, type=Path, help="local bundle directory")
    parser.add_argument("--region", help="factual local vantage label")
    parser.add_argument(
        "--resolver",
        action="append",
        default=[],
        type=_cli_resolver,
        help="resolver IP literal; repeat for bounded comparisons",
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--record-type",
        default=None,
        type=_cli_record_type,
        metavar="TYPE",
        help="single DNS record type: A, AAAA, NS, SOA, DS, or DNSKEY (default: A)",
    )
    scope.add_argument(
        "--health-check",
        action="store_true",
        help="query A, AAAA, NS, and SOA using a bounded health-check profile",
    )
    parser.add_argument(
        "--samples",
        type=_cli_samples,
        metavar="COUNT",
        help="independent samples per query shape, 1-3 (health-check default: 2)",
    )
    parser.add_argument(
        "--timeout",
        default=5.0,
        type=_cli_timeout,
        metavar="SECONDS",
        help="per-command timeout, greater than 0 and at most 10 seconds",
    )
    parser.add_argument(
        "--no-public-resolvers",
        action="store_true",
        help="reject globally routable resolver IPs and use no automatic public resolver",
    )
    parser.add_argument(
        "--acknowledge-internal-public-query",
        action="store_true",
        help="acknowledge that an internal target may be disclosed to an explicit public resolver",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="run the five baseline layers: local, dnssec, public, trace, authoritative",
    )
    parser.add_argument(
        "--dnssec",
        action="store_true",
        help="add the signature layer: whether the name is signed and whether it validates",
    )
    parser.add_argument(
        "--public-resolvers",
        action="store_true",
        help="add the public resolver comparison layer (8.8.8.8, 180.76.76.76, 114.114.114.114)",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="add the delegation layer: follow the chain from the root servers down",
    )
    parser.add_argument(
        "--authoritative",
        action="store_true",
        help="add the authoritative layer: ask the zone's own servers without recursion",
    )
    parser.add_argument(
        "--regions",
        default=None,
        metavar="CC,CC",
        help=(
            "remote observation from these two-letter countries; sends only the queried "
            "name and record type off this machine, and requires --acknowledge-remote-query"
        ),
    )
    parser.add_argument(
        "--acknowledge-remote-query",
        action="store_true",
        help="acknowledge that --regions discloses the queried name to a remote service",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _probe_argument_parser()
    args = parser.parse_args(argv)
    try:
        normalized = normalize_target(args.target)
        target = normalized["hostname"] or normalized["ip"]
        if args.region is not None and (
            not args.region.strip()
            or len(args.region) > 128
            or any(ord(char) < 32 or ord(char) == 127 for char in args.region)
        ):
            raise ValueError("region must be non-empty text without control characters")
        if len(args.resolver) > _CLI_MAX_RESOLVERS:
            raise ValueError(
                "at most {0} resolver inputs are allowed".format(_CLI_MAX_RESOLVERS)
            )
        if len(set(args.resolver)) != len(args.resolver):
            raise ValueError("resolver inputs must be unique")
        public_resolvers = [
            resolver for resolver in args.resolver
            if ipaddress.ip_address(resolver).is_global
        ]
        if args.no_public_resolvers and public_resolvers:
            raise ValueError(
                "--no-public-resolvers cannot be combined with a public resolver IP"
            )
        internal_public_query = _is_internal_name(normalized) and bool(public_resolvers)
        layers = ["local"]
        for flag, layer in (
            (args.dnssec, "dnssec"),
            (args.public_resolvers, "public"),
            (args.trace, "trace"),
            (args.authoritative, "authoritative"),
        ):
            if args.baseline or flag:
                layers.append(layer)
        if args.no_public_resolvers:
            if args.public_resolvers:
                raise ValueError(
                    "--no-public-resolvers cannot be combined with --public-resolvers"
                )
            # --baseline implies the public layer; an explicit opt-out drops that one
            # layer instead of failing the whole run.
            layers = [layer for layer in layers if layer != "public"]
        # The public layer sends the queried name to third-party resolvers, which is the
        # same disclosure the explicit --resolver path already gates behind an ack.
        internal_layer_query = _is_internal_name(normalized) and "public" in layers
        if (internal_public_query or internal_layer_query) and not args.acknowledge_internal_public_query:
            raise ValueError(
                "internal target with a public resolver requires "
                "--acknowledge-internal-public-query"
            )
        _validate_cli_output_dir(args.output_dir)
        regions = normalize_regions(args.regions)
        if args.acknowledge_remote_query and not regions:
            raise ValueError("--acknowledge-remote-query requires --regions")
        remote_blocked = bool(regions) and _is_internal_name(normalized)
    except ValueError as exc:
        parser.error(str(exc))

    disclosed = list(public_resolvers)
    if internal_layer_query:
        disclosed.extend(
            address for address in _PUBLIC_RESOLVERS if address not in disclosed
        )
    if internal_public_query or internal_layer_query:
        print(
            "WARNING: querying {0} through public resolver(s) {1} can disclose the internal target.".format(
                target, ", ".join(disclosed)
            ),
            file=sys.stderr,
            flush=True,
        )

    if regions and not remote_blocked:
        if args.acknowledge_remote_query:
            print(
                "WARNING: remote observation will send the queried name {0} and its record "
                "type to {1} for probes in {2}. Nothing else leaves this machine.".format(
                    target, _REMOTE_API_HOST, ", ".join(regions)
                ),
                file=sys.stderr,
                flush=True,
            )
        else:
            print(
                "NOTICE: --regions was ignored because --acknowledge-remote-query was not "
                "given; no name left this machine.",
                file=sys.stderr,
                flush=True,
            )
    if remote_blocked:
        print(
            "NOTICE: {0} looks internal, so remote observation is refused outright; "
            "an internal name cannot be recalled from a third party's logs.".format(target),
            file=sys.stderr,
            flush=True,
        )

    health_profile = args.health_check or (args.baseline and args.record_type is None)
    record_types = (
        list(_HEALTH_CHECK_RECORD_TYPES) if health_profile else [args.record_type or "A"]
    )
    samples = args.samples if args.samples is not None else (2 if health_profile else 1)
    profile = "health" if health_profile else "record"

    evidence = _collect_cli_evidence(
        target,
        args.resolver,
        record_types,
        samples,
        profile,
        args.region,
        args.timeout,
        args.no_public_resolvers,
        args.acknowledge_internal_public_query,
        layers,
        regions,
        args.acknowledge_remote_query,
    )
    try:
        paths = write_bundle(evidence, args.output_dir)
    except (OSError, ValueError) as exc:
        parser.error("could not write local bundle: {0}".format(exc))
    print(paths["json"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
