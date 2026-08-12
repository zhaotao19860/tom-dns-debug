"""Deterministic, offline interpretation of DNS probe evidence."""

import argparse
import importlib.util
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit


_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b("
    r"api[ _-]?keys?|(?:access|refresh|auth)[ _-]?tokens?|"
    r"client[ _-]?secrets?|tokens?|secrets?|passwords?|"
    r"passphrases?|credentials?|authorization|session[ _-]?ids?"
    r")\b(\s*[:=]\s*)"
    r"(?:(?:basic|bearer|digest|negotiate)\s+[^\s,;&#]+|\"[^\"]*\"|'[^']*'|[^\s,;&#]+)"
)
_TRANSPORT_ALIASES = {
    "dns-over-tcp": "tcp",
    "dns_over_tcp": "tcp",
    "tcp53": "tcp",
    "dns-over-udp": "udp",
    "dns_over_udp": "udp",
    "udp53": "udp",
}
_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    16: "BADVERS",
}
# Plain-language names for the record types this skill can collect automatically.
_RECORD_TYPE_LABELS = {
    "A": "IPv4 地址记录（A）",
    "AAAA": "IPv6 地址记录（AAAA）",
    "NS": "权威服务器记录（NS）",
    "SOA": "区域起始记录（SOA）",
    "DS": "签名指纹记录（DS）",
    "DNSKEY": "签名公钥记录（DNSKEY）",
    "CNAME": "别名记录（CNAME）",
}
_FINDING_KEYS = (
    "category",
    "severity",
    "confidence",
    "status",
    "summary",
    "supporting_probe_ids",
    "contradictory_probe_ids",
    "next_checks",
)
_MISSING = object()
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_REGIONAL_WINDOW_SECONDS = 600.0


def _redact_url(match: re.Match) -> str:
    text = match.group(0)
    trailing = ""
    while text and text[-1] in ").,;]}":
        trailing = text[-1] + trailing
        text = text[:-1]
    try:
        parsed = urlsplit(text)
        netloc = parsed.netloc.rsplit("@", 1)[-1]
        cleaned = urlunsplit((
            parsed.scheme,
            netloc,
            parsed.path,
            "[REDACTED]" if parsed.query else "",
            "[REDACTED]" if parsed.fragment else "",
        ))
    except ValueError:
        cleaned = text.split("?", 1)[0].split("#", 1)[0]
        if "?" in text:
            cleaned += "?[REDACTED]"
        if "#" in text:
            cleaned += "#[REDACTED]"
    return cleaned + trailing


def redact_text(value: str) -> str:
    """Remove URL-only data and bounded, likely secret assignments."""
    if not isinstance(value, str):
        raise TypeError("value must be text")
    redacted = _URL.sub(_redact_url, value)
    return _SECRET_ASSIGNMENT.sub(
        lambda match: match.group(1) + match.group(2) + "[REDACTED]",
        redacted,
    )


def _normalized_label(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text.rstrip(".") or None


def _normalized_transport(value: Any) -> Optional[str]:
    label = _normalized_label(value)
    return _TRANSPORT_ALIASES.get(label, label)


def _normalized_qname(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        value = value.get("hostname") or value.get("ip") or value.get("input")
    if value is None:
        return None
    text = str(value).strip()
    if "://" in text:
        try:
            text = urlsplit(text).hostname or ""
        except ValueError:
            return None
    return _normalized_label(text)


def _normalized_qtype(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().upper().rstrip(".")
    return text or None


def _normalized_status(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return _RCODE_NAMES.get(value, str(value))
    text = str(value).strip().upper()
    if text.startswith("RCODE="):
        text = text.split("=", 1)[1].strip()
    if text.isdigit():
        return _RCODE_NAMES.get(int(text), text)
    return text or None


def _normalized_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return ""
    return str(value).strip().lower().rstrip(".")


def _normalized_answer(value: Any, qtype: Optional[str] = None) -> Tuple[str, ...]:
    if isinstance(value, dict):
        name = _normalized_scalar(value.get("name"))
        record_type = _normalized_scalar(value.get("type") or value.get("record_type")).upper()
        effective_qtype = record_type or qtype
        data = value.get("data", value.get("value", value.get("address", "")))
        if effective_qtype in {"TXT", "SPF"}:
            chunks = data if isinstance(data, list) else [data]
            preserved = tuple(str(item).strip() for item in chunks if str(item).strip())
            return tuple(item for item in (name, record_type, *preserved) if item)
        if isinstance(data, list):
            data_text = " ".join(_normalized_scalar(item) for item in data)
        else:
            data_text = _normalized_scalar(data)
        return tuple(item for item in (name, record_type, data_text) if item)
    if isinstance(value, (list, tuple)):
        if qtype in {"TXT", "SPF"}:
            return tuple(str(item).strip() for item in value)
        return tuple(_normalized_scalar(item) for item in value)
    if qtype in {"TXT", "SPF"}:
        return (str(value).strip(),)
    return (_normalized_scalar(value),)


_VALIDATION_RECORD_TYPES = frozenset({"RRSIG", "NSEC", "NSEC3", "NSEC3PARAM"})


def _normalized_answers(observation: dict) -> Optional[Tuple[Tuple[str, ...], ...]]:
    if "answers" not in observation:
        return None
    answers = observation.get("answers")
    if answers is None:
        return None
    if not isinstance(answers, (list, tuple)):
        answers = [answers]
    qtype = observation.get("_qtype") or _normalized_qtype(
        observation.get("qtype", observation.get("query_type", observation.get("record_type")))
    )
    normalized = set(_normalized_answer(answer, qtype) for answer in answers)
    if qtype not in _VALIDATION_RECORD_TYPES:
        # A query asked with +dnssec carries signature records the same query without
        # the flag never returns; comparing them verbatim would invent a disagreement.
        normalized = {
            answer for answer in normalized
            if not (len(answer) >= 2 and answer[1].upper() in _VALIDATION_RECORD_TYPES)
        }
    return tuple(sorted(normalized))


def _delivered_query_type(item: dict) -> bool:
    """True when the answer actually settles the question that was asked.

    An authoritative server that returns only a CNAME pointing into another zone
    has not answered the question, so comparing it with a recursive answer that
    followed the alias would manufacture a disagreement that does not exist.
    REFUSED and SERVFAIL are likewise no answer at all, only a server that would
    not or could not respond.
    """
    if item["status"] in {"REFUSED", "SERVFAIL"}:
        return False
    if item["status"] in {"NXDOMAIN", "NODATA"}:
        return True
    answers = item["_answers"]
    if not answers:
        return False
    qtype = item["_qtype"]
    if qtype is None:
        return True
    for answer in answers:
        if len(answer) < 2:
            # A bare address list carries no record type of its own.
            return True
        if answer[1].upper() == qtype:
            return True
    return False


def _normalized_observed_at(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _normalized_ttls(observation: dict) -> Optional[Tuple[Any, ...]]:
    value = observation.get("ttls", observation.get("ttl", _MISSING))
    if value is _MISSING and isinstance(observation.get("answers"), (list, tuple)):
        embedded = [
            answer["ttl"] for answer in observation["answers"]
            if isinstance(answer, dict) and answer.get("ttl") is not None
        ]
        if embedded:
            value = embedded
    if value is _MISSING or value is None:
        return None
    values = value if isinstance(value, (list, tuple)) else [value]
    normalized = []
    for item in values:
        try:
            number = float(item)
            normalized.append(int(number) if number.is_integer() else number)
        except (TypeError, ValueError):
            normalized.append(_normalized_scalar(item))
    return tuple(sorted(set(normalized), key=lambda item: (str(type(item)), str(item))))


def _probe_id(observation: dict, index: int) -> str:
    value = observation.get("id", observation.get("probe_id"))
    return str(value) if value is not None else "observation-{0}".format(index + 1)


def _normalize_observation(
    observation: dict,
    index: int,
    fallback_qname: Any = None,
) -> dict:
    item = dict(observation)
    item["id"] = _probe_id(item, index)
    item["vantage"] = _normalized_label(item.get("vantage"))
    item["resolver"] = _normalized_label(item.get("resolver"))
    item["transport"] = _normalized_transport(item.get("transport"))
    item["status"] = _normalized_status(item.get("status", item.get("rcode")))
    item["role"] = _normalized_label(item.get("role"))
    item["_qname"] = _normalized_qname(
        item.get("qname", item.get("query_name", item.get("question_name", item.get("_qname", fallback_qname))))
    )
    item["_qtype"] = _normalized_qtype(
        item.get("qtype", item.get("query_type", item.get("record_type", item.get("_qtype"))))
    )
    item["_observed_at"] = _normalized_observed_at(
        item.get("observed_at", item.get("timestamp", item.get("started_at", item.get("collected_at"))))
    )
    item["_answers"] = _normalized_answers(item)
    item["_ttls"] = _normalized_ttls(item)
    return item


def _observations_from_evidence(evidence: dict) -> List[dict]:
    fallback_qname = evidence.get("target")
    supplied = evidence.get("observations")
    if isinstance(supplied, list):
        source = supplied
    else:
        source = []
        region = None
        environment = evidence.get("environment")
        if isinstance(environment, dict):
            region = environment.get("region")
        probes = evidence.get("probes")
        if isinstance(probes, list):
            for probe in probes:
                if not isinstance(probe, dict):
                    continue
                item = dict(probe)
                if "vantage" not in item:
                    item["vantage"] = region
                if "answers" not in item:
                    parsed = item.get("parsed")
                    if isinstance(parsed, dict) and "addresses" in parsed:
                        item["answers"] = list(parsed.get("addresses") or [])
                source.append(item)
    remote = evidence.get("remote_observations")
    if isinstance(remote, list):
        # Remote records are observations in their own right, not local command runs, so
        # they live under their own key; both sets have to reach the comparison.
        source = list(source) + [item for item in remote if isinstance(item, dict)]
    return [
        _normalize_observation(item, index, fallback_qname)
        for index, item in enumerate(source)
        if isinstance(item, dict)
    ]


def _public_group(group: dict) -> dict:
    observations = []
    for item in group["observations"]:
        observations.append({
            "probe_id": item["id"],
            "qname": item["_qname"],
            "qtype": item["_qtype"],
            "status": item["status"],
            "answers": [list(answer) for answer in item["_answers"]]
            if item["_answers"] is not None else None,
            "ttls": list(item["_ttls"]) if item["_ttls"] is not None else None,
            "observed_at": item["_observed_at"].isoformat().replace("+00:00", "Z")
            if item["_observed_at"] is not None else None,
        })
    return {
        "qname": group["qname"],
        "qtype": group["qtype"],
        "vantage": group["vantage"],
        "resolver": group["resolver"],
        "transport": group["transport"],
        "role": group["role"],
        "probe_ids": [item["id"] for item in group["observations"]],
        "observations": observations,
    }


def _sorted_known(values: set) -> list:
    return sorted((value for value in values if value is not None), key=str)


def compare_regional_answers(observations: List[dict]) -> dict:
    """Build a normalized vantage/resolver/transport matrix."""
    if not isinstance(observations, list):
        raise TypeError("observations must be a list")
    normalized = [
        _normalize_observation(item, index)
        for index, item in enumerate(observations)
        if isinstance(item, dict)
    ]
    grouped: Dict[Tuple[Optional[str], ...], dict] = {}
    for item in normalized:
        key = (
            item["_qname"], item["_qtype"], item["vantage"],
            item["resolver"], item["transport"], item["role"],
        )
        grouped.setdefault(key, {
            "qname": key[0],
            "qtype": key[1],
            "vantage": key[2],
            "resolver": key[3],
            "transport": key[4],
            "role": key[5],
            "observations": [],
        })["observations"].append(item)

    comparable: Dict[Tuple[str, str, str, str, str], Dict[str, List[dict]]] = {}
    for item in normalized:
        key = _regional_cohort_key(item)
        if key is not None and item["vantage"] is not None:
            comparable.setdefault(key, {}).setdefault(item["vantage"], []).append(item)
    divergent_fields = set()
    for by_vantage in comparable.values():
        if len(by_vantage) < 2:
            continue
        for field, internal in (("status", "status"), ("answers", "_answers"), ("ttls", "_ttls")):
            signatures = set()
            for samples in by_vantage.values():
                values = frozenset(
                    item[internal] for item in samples if item[internal] is not None
                )
                if values:
                    signatures.add(values)
            if len(signatures) > 1:
                divergent_fields.add(field)
    divergent = sorted(divergent_fields)
    regional_semantics = _regional_semantics(normalized)
    dimensions = {
        "qname": _sorted_known({item["_qname"] for item in normalized}),
        "qtype": _sorted_known({item["_qtype"] for item in normalized}),
        "vantage": _sorted_known({item["vantage"] for item in normalized}),
        "resolver": _sorted_known({item["resolver"] for item in normalized}),
        "transport": _sorted_known({item["transport"] for item in normalized}),
        "role": _sorted_known({item["role"] for item in normalized}),
    }
    ordered_groups = sorted(
        grouped.values(),
        key=lambda group: tuple(value or "" for value in (
            group["qname"], group["qtype"], group["vantage"],
            group["resolver"], group["transport"], group["role"],
        )),
    )
    return {
        "groups": [_public_group(group) for group in ordered_groups],
        "dimensions": dimensions,
        "divergent_fields": divergent,
        "sufficient_for_regional_claim": bool(regional_semantics["comparable_support"]),
        "temporal_window_seconds": _REGIONAL_WINDOW_SECONDS,
        "temporally_comparable": bool(regional_semantics["comparable_support"]),
    }


def _unique_ids(items: List[dict]) -> List[str]:
    result = []
    for item in items:
        identifier = item["id"]
        if identifier not in result:
            result.append(identifier)
    return result


def _finding(
    category: str,
    severity: str,
    confidence: str,
    status: str,
    summary: str,
    supporting: List[dict],
    contradictory: Optional[List[dict]],
    next_checks: List[str],
) -> dict:
    finding = {
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "summary": summary,
        "supporting_probe_ids": _unique_ids(supporting),
        "contradictory_probe_ids": _unique_ids(contradictory or []),
        "next_checks": list(next_checks),
    }
    return {key: finding[key] for key in _FINDING_KEYS}


def _query_identity(item: dict) -> Tuple[Optional[str], Optional[str]]:
    return item["_qname"], item["_qtype"]


def _has_known_query_identity(item: dict) -> bool:
    return all(_query_identity(item))


def _same_query(left: dict, right: dict) -> bool:
    return (
        _has_known_query_identity(left)
        and _has_known_query_identity(right)
        and _query_identity(left) == _query_identity(right)
    )


def _same_transport_cohort(left: dict, right: dict) -> bool:
    dimensions = ("vantage", "resolver", "role")
    return (
        _same_query(left, right)
        and all(left[field] is not None and left[field] == right[field] for field in dimensions)
    )


def _has_cname_loop(item: dict) -> bool:
    if item.get("cname_loop"):
        return True
    edges = item.get("cname_edges")
    if isinstance(edges, list):
        graph: Dict[str, set] = {}
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            owner = _normalized_label(edge.get("owner"))
            target = _normalized_label(edge.get("target"))
            if owner is not None and target is not None:
                graph.setdefault(owner, set()).add(target)

        active = set()
        complete = set()

        def visit(node: str) -> bool:
            if node in active:
                return True
            if node in complete:
                return False
            active.add(node)
            if any(visit(target) for target in graph.get(node, ())):
                return True
            active.remove(node)
            complete.add(node)
            return False

        if graph:
            return any(visit(node) for node in tuple(graph) if node not in complete)

    chain = item.get("cname_chain")
    if not isinstance(chain, list):
        return False
    normalized = [_normalized_label(name) for name in chain]
    normalized = [name for name in normalized if name is not None]
    if len(normalized) == 2 and normalized[0] == normalized[1]:
        return True
    collapsed = [
        name for index, name in enumerate(normalized)
        if index == 0 or name != normalized[index - 1]
    ]
    return len(collapsed) != len(set(collapsed))


def _dnssec_is_bogus(item: dict) -> bool:
    dnssec = item.get("dnssec")
    if isinstance(dnssec, dict):
        state = dnssec.get("validation", dnssec.get("status"))
    else:
        state = item.get("dnssec_status", dnssec)
    return _normalized_label(state) in {"bogus", "failed", "invalid", "validation_failed"}


def _nameservers(item: dict) -> Optional[Tuple[str, ...]]:
    values = item.get("nameservers")
    if not isinstance(values, (list, tuple)):
        return None
    return tuple(sorted(filter(None, (_normalized_label(value) for value in values))))


def _regional_cohort_key(item: dict) -> Optional[Tuple[str, str, str, str, str]]:
    values = (
        item["_qname"], item["_qtype"], item["resolver"],
        item["transport"], item["role"],
    )
    if not all(values):
        return None
    return values  # type: ignore[return-value]


def _independent_corroboration(item: dict, observations: List[dict]) -> List[dict]:
    candidates = [
        other for other in observations
        if other["id"] != item["id"]
        and _same_query(item, other)
        and other["vantage"] == item["vantage"]
        and other["_answers"] == item["_answers"]
        and other["role"] in {"recursive", "authoritative"}
    ]
    roles = {item["role"]} | {other["role"] for other in candidates}
    if {"recursive", "authoritative"}.issubset(roles):
        return candidates
    return []


def _stable_regional_answer(
    samples: List[dict],
    observations: List[dict],
) -> Tuple[Optional[Tuple[Tuple[str, ...], ...]], List[dict]]:
    answers = {item["_answers"] for item in samples if item["_answers"] is not None}
    if len(answers) != 1:
        return None, []
    answer = next(iter(answers))
    if len({item["id"] for item in samples}) < 2:
        return None, []
    timestamps = [item["_observed_at"] for item in samples]
    if any(timestamp is None for timestamp in timestamps):
        return None, []
    known_timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
    if (max(known_timestamps) - min(known_timestamps)).total_seconds() > _REGIONAL_WINDOW_SECONDS:
        return None, []
    return answer, samples


def _regional_semantics(observations: List[dict]) -> dict:
    cohorts: Dict[Tuple[str, str, str, str, str], Dict[str, List[dict]]] = {}
    for item in observations:
        key = _regional_cohort_key(item)
        if key is None or item["vantage"] is None or item["_answers"] is None:
            continue
        cohorts.setdefault(key, {}).setdefault(item["vantage"], []).append(item)

    comparable_support = []
    divergent_support = []
    saw_unstable_divergence = False
    saw_temporal_incomparability = False
    for by_vantage in cohorts.values():
        if len(by_vantage) < 2:
            continue
        raw_answers = {
            item["_answers"]
            for samples in by_vantage.values()
            for item in samples
            if item["_answers"] is not None
        }
        stable_by_vantage = []
        for samples in by_vantage.values():
            answer, evidence = _stable_regional_answer(samples, observations)
            if answer is not None:
                stable_by_vantage.append((answer, evidence))
        if len(stable_by_vantage) >= 2:
            stable_evidence = [
                item for _, evidence in stable_by_vantage for item in evidence
            ]
            timestamps = [item["_observed_at"] for item in stable_evidence]
            if (any(timestamp is None for timestamp in timestamps)
                    or (max(timestamp for timestamp in timestamps if timestamp is not None)
                        - min(timestamp for timestamp in timestamps if timestamp is not None)).total_seconds()
                    > _REGIONAL_WINDOW_SECONDS):
                saw_temporal_incomparability = True
                continue
            comparable_support.extend(stable_evidence)
            if len({answer for answer, _ in stable_by_vantage}) >= 2:
                divergent_support.extend(stable_evidence)
            elif len(raw_answers) >= 2:
                saw_unstable_divergence = True
        elif len(raw_answers) >= 2:
            saw_unstable_divergence = True
    return {
        "comparable_support": comparable_support,
        "divergent_support": divergent_support,
        "unstable_divergence": saw_unstable_divergence,
        "temporal_incomparability": saw_temporal_incomparability,
    }


def _resolver_text(value: Any) -> str:
    """Plain-language name for a resolver label."""
    if not value:
        return "未知"
    text = str(value)
    return "本机（系统默认）" if text == "system" else _safe_text(text)


def _vantage_text(value: Any) -> str:
    """Labels are normalized to lower case; a country code still reads as one."""
    text = _safe_text(value)
    return text.upper() if len(text) == 2 and text.isalpha() else text


def _is_truncated(item: dict) -> bool:
    if item.get("tc"):
        return True
    flags = item.get("flags")
    if isinstance(flags, str):
        return "tc" in flags.lower().split()
    if isinstance(flags, (list, tuple, set)):
        return any(_normalized_label(flag) == "tc" for flag in flags)
    return False


def _resolution_success_findings(observations: List[dict]) -> List[dict]:
    buckets: Dict[Tuple[Any, ...], List[dict]] = {}
    for item in observations:
        key = (
            item.get("_qname"),
            item.get("_qtype"),
            item.get("resolver"),
            item.get("vantage"),
            item.get("role"),
        )
        if key[0] and key[1]:
            buckets.setdefault(key, []).append(item)

    findings = []
    for key, items in buckets.items():
        successful = [
            item for item in items
            if item.get("status") == "NOERROR"
            and item.get("_answers")
            and not item.get("timed_out")
            and not item.get("error")
            and not _is_truncated(item)
        ]
        if not successful:
            continue

        answer_groups: Dict[Tuple[Tuple[str, ...], ...], List[dict]] = {}
        for item in successful:
            answer_groups.setdefault(item["_answers"], []).append(item)
        supporting = max(
            answer_groups.values(),
            key=lambda group: (len(group), tuple(_unique_ids(group))),
        )
        expected_answers = supporting[0]["_answers"]
        contradictory = [
            item for item in items
            if item.get("status") not in {None, "NOERROR"}
            or (
                item.get("status") == "NOERROR"
                and item.get("_answers")
                and item.get("_answers") != expected_answers
            )
        ]
        supporting_ids = _unique_ids(supporting)
        transports = {item.get("transport") for item in supporting}
        confirmed = (
            (len(supporting_ids) >= 2 or {"udp", "tcp"}.issubset(transports))
            and not contradictory
        )
        qname, qtype, resolver, vantage, _role = key
        scope = "解析器：{0}".format(_resolver_text(resolver))
        if vantage:
            scope += "，观测点：{0}".format(vantage)
        if _delivered_query_type(supporting[0]):
            summary = "{0} 的 {1} 查询返回了稳定的 {1} 记录（{2}）。".format(qname, qtype, scope)
        else:
            # A name that is an alias legitimately has no NS or SOA of its own;
            # calling that "a stable non-empty answer" reads as a pass it never earned.
            summary = (
                "{0} 的 {1} 查询稳定返回 NOERROR，但答案里只有别名（CNAME），"
                "没有 {1} 记录本身；对于指向别名的名称这是正常的（{2}）。"
            ).format(qname, qtype, scope)
        findings.append(_finding(
            "resolution_succeeded",
            "info",
            "high" if confirmed else "medium",
            "confirmed" if confirmed else "high_probability",
            summary,
            supporting,
            contradictory,
            [] if confirmed else ["通过独立重复样本或 TCP 查询确认当前成功结果。"],
        ))
    return findings


def _regional_analysis_requested(evidence: dict, observations: List[dict]) -> bool:
    analysis_scope = evidence.get("analysis_scope")
    if isinstance(analysis_scope, dict) and analysis_scope.get("regional") is True:
        return True
    environment = evidence.get("environment")
    if isinstance(environment, dict) and environment.get("region"):
        return True
    return any(item.get("vantage") for item in observations)


def _dnssec_findings(
    evidence: dict, observations: List[dict], already_bogus: bool
) -> List[dict]:
    """Report signing state only when the DNSSEC queries actually ran."""
    assessment = evidence.get("dnssec")
    if not isinstance(assessment, dict):
        return []
    validation = assessment.get("validation")
    supporting_ids = set(assessment.get("supporting_probe_ids") or [])
    supporting = [item for item in observations if item["id"] in supporting_ids]
    if not supporting:
        return []
    apex = assessment.get("apex") or "该域名"
    reason = assessment.get("reason") or ""
    if validation == "insecure":
        return [_finding(
            "dnssec_unsigned", "info", "high", "confirmed",
            "{0} 未启用 DNSSEC 签名，因此无签名可校验；这是域名持有者的选择，不是故障。".format(apex),
            supporting, [], ["如需防篡改保护，请由域名持有者在注册商处启用 DNSSEC。"],
        )]
    if validation == "secure":
        return [_finding(
            "dnssec_valid", "info", "high", "confirmed",
            "{0} 已启用 DNSSEC，本次查询的签名通过了解析器校验。".format(apex),
            supporting, [], ["定期核对 DS 与 DNSKEY 的密钥标签，换钥期间尤其要核对。"],
        )]
    if validation == "indeterminate" and not already_bogus:
        return [_finding(
            "dnssec_indeterminate", "low", "low", "unverified",
            "无法判定 {0} 的 DNSSEC 校验状态：{1}".format(apex, reason),
            supporting, [],
            [
                "换一台会做校验的解析器复测同一查询。",
                "分别核对 DS、DNSKEY 与 RRSIG 三者是否齐全且密钥标签一致。",
            ],
        )]
    return []


def _divergence_next_checks(qname: Optional[str], authoritative: List[dict]) -> List[str]:
    """Next check for differing resolver answers, minus any check already run."""
    matching = [item for item in authoritative if item["_qname"] == qname]
    if not matching:
        return ["直接询问权威服务器，看每台解析器的答案是否都在权威给出的地址集合内。"]
    if any(_delivered_query_type(item) for item in matching):
        return ["对照本报告“直接问权威服务器”一节，确认各解析器给出的答案都在权威给出的范围内。"]
    chain = _alias_chain(matching)
    if chain:
        return ["权威服务器只给出别名，最终地址由 {0} 决定；对它单独跑一次检查即可取得权威地址集合。".format(
            _safe_text(chain[-1]).rstrip("."),
        )]
    return ["权威服务器没有给出这一类型的记录；先确认它是否登记在别的名称上。"]


_UNROUTABLE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
    "::1/128", "fc00::/7", "fe80::/10", "::/128",
))


def _is_unroutable(address) -> bool:
    """An address only reachable inside the network that answered with it.

    Deliberately narrower than ``is_private``, which also covers the documentation
    ranges (192.0.2.0/24, 198.51.100.0/24) that stand in for public addresses in
    examples and fixtures — calling those 内网地址 would be plainly wrong.
    """
    return any(
        address in network
        for network in _UNROUTABLE_NETWORKS
        if network.version == address.version
    )


def _unroutable_answers(item: dict) -> List[str]:
    """Answer addresses no client outside the answering network can reach."""
    found: List[str] = []
    ipv4, ipv6 = _addresses_by_family([item])
    for value in ipv4 + ipv6:
        if _is_unroutable(ipaddress.ip_address(value)) and value not in found:
            found.append(value)
    return found


def _offnet_resolver(item: dict) -> bool:
    """True when we deliberately asked a resolver outside this machine's network."""
    resolver = item["resolver"]
    if not resolver or resolver == "system":
        return False
    try:
        address = ipaddress.ip_address(resolver)
    except ValueError:
        return False
    return not _is_unroutable(address)


def _private_answer_findings(evidence: dict, observations: List[dict]) -> List[dict]:
    """An off-net resolver handing back an internal address is a usable clue.

    Split-horizon DNS makes that answer correct inside the network that owns the
    address, so this stays a low-severity clue about where the answer works, never
    a verdict on the name. For an internal target it is the expected answer and no
    finding is raised at all.
    """
    if _internal_names(evidence, observations):
        return []
    support = [
        item for item in observations
        if _offnet_resolver(item) and _unroutable_answers(item)
    ]
    if not support:
        return []
    addresses: List[str] = []
    for item in support:
        for value in _unroutable_answers(item):
            if value not in addresses:
                addresses.append(value)
    resolvers = _sorted_known({item["resolver"] for item in support})
    return [_finding(
        "private_address_answer", "low", "medium", "high_probability",
        "外部解析器（{0}）给出的是内网地址（{1}）——公网上到不了这个地址，"
        "除非这台机器就在那个内网里，否则照着它连接会失败。".format(
            "、".join(resolvers), "、".join(addresses),
        ),
        support, [],
        ["换另一家公共 DNS 或直接问权威服务器，核对同一个名字的公网地址。"],
    )]


def _public_resolver_findings(observations: List[dict]) -> List[dict]:
    """Compare what different resolvers hand back for the same question."""
    authoritative = [
        item for item in observations
        if item["role"] in {"authoritative", "child_authority"}
        and item["status"] == "NOERROR"
    ]
    usable = [
        item for item in observations
        if item["role"] == "recursive" and item["status"]
        and _has_known_query_identity(item)
    ]
    findings = []
    # UDP and TCP are separate cohorts: a transport mismatch is evidence about the
    # path, not evidence that two resolver implementations disagree.
    by_query: Dict[
        Tuple[Optional[str], Optional[str], Optional[str]], Dict[str, List[dict]]
    ] = {}
    for item in usable:
        identity = (*_query_identity(item), item["transport"])
        by_query.setdefault(identity, {}).setdefault(
            item["resolver"] or "unknown", []
        ).append(item)
    for identity, by_resolver in sorted(by_query.items(), key=lambda pair: str(pair[0])):
        if len(by_resolver) < 2:
            continue
        supporting = [item for group in by_resolver.values() for item in group]
        resolver_signatures = {
            resolver: {
                (item["status"], item["_answers"])
                for item in group
            }
            for resolver, group in by_resolver.items()
        }
        answer_sets = set(frozenset(signatures) for signatures in resolver_signatures.values())
        resolvers = "、".join(sorted(by_resolver))
        if len(answer_sets) == 1:
            findings.append(_finding(
                "public_resolver_agreement", "info", "high", "confirmed",
                "{0} 的 {1} 查询在 {2} 上返回完全相同的答案。".format(
                    identity[0], identity[1], resolvers,
                ),
                supporting, [], [],
            ))
        else:
            # An SOA or NS difference is not an address difference; naming the wrong thing
            # sends the reader looking for a hijacked address that no probe reported.
            if (identity[1] or "").upper() in {"A", "AAAA"}:
                subject, because = "地址", "使用 CDN 或按地区解析的域名本来就会这样"
            else:
                subject, because = "答案", "各家缓存的版本新旧不同也会这样"
            findings.append(_finding(
                "public_resolver_divergence", "low", "low", "unverified",
                "{0} 的 {1} 查询在不同解析器上返回的{2}不完全相同（{3}）；"
                "{4}，不能据此判定被篡改。".format(
                    identity[0], identity[1], subject, resolvers, because,
                ),
                supporting, [],
                _divergence_next_checks(identity[0], authoritative),
            ))
    return findings


def _soa_zone_serial(item: dict) -> Optional[Tuple[Tuple[str, str], int]]:
    """The zone identity and serial of a lone SOA answer, as ``((mname, rname), serial)``.

    Anything else — several records, or rdata dig did not lay out as the seven standard
    fields — returns ``None`` rather than a guess.
    """
    answers = item.get("_answers") or ()
    if len(answers) != 1:
        return None
    entry = answers[0]
    if len(entry) >= 3:
        if entry[1] != "SOA":
            return None
        rdata = entry[2]
    elif len(entry) == 1 and (item.get("_qtype") or "").upper() == "SOA":
        # A manual observation may carry the rdata alone, with the type only on the query.
        rdata = entry[0]
    else:
        return None
    fields = _safe_text(rdata).split()
    if len(fields) != 7:
        return None
    try:
        serial = int(fields[2])
    except ValueError:
        return None
    return (fields[0].lower(), fields[1].lower()), serial


def _is_stale_soa_copy(recursive_item: dict, authoritative_items: List[dict]) -> bool:
    """Same zone, lower serial: a cached copy of an older version, not a contradiction.

    The serial only ever moves forward, so a resolver holding a smaller one is holding
    an entry whose TTL has not run out yet. Calling that a divergence would make cache
    behaviour every large zone shows look like tampering.
    """
    cached = _soa_zone_serial(recursive_item)
    if cached is None:
        return False
    zone, serial = cached
    references = [
        entry for entry in (_soa_zone_serial(item) for item in authoritative_items)
        if entry is not None
    ]
    if not references:
        return False
    return all(
        other_zone == zone and other_serial > serial
        for other_zone, other_serial in references
    )


def classify_evidence(evidence: dict) -> List[dict]:
    """Return conservative findings based only on supplied observations."""
    if not isinstance(evidence, dict):
        raise TypeError("evidence must be a mapping")
    observations = _observations_from_evidence(evidence)
    if not observations:
        return [_finding(
            "insufficient_evidence", "low", "low", "unverified",
            "没有可用于分类的 DNS 观测。", [], [],
            ["补充至少一次带探针 ID 的 DNS 查询。"],
        )]

    findings = []
    by_status: Dict[str, List[dict]] = {}
    for item in observations:
        if item["status"]:
            by_status.setdefault(item["status"], []).append(item)

    findings.extend(_resolution_success_findings(observations))

    timed_out = [item for item in observations if item.get("timed_out")]
    if timed_out:
        findings.append(_finding(
            "query_timeout", "medium", "high", "confirmed",
            "探针在有界等待时间内未收到可解析的 DNS 结果；这不单独证明 DNS 根因。",
            timed_out, [],
            ["用同一个解析器、同一种传输方式（UDP/TCP）再查一次，并检查网络是否通。"],
        ))
    execution_errors = [
        item for item in observations
        if item.get("error") and not item.get("timed_out")
    ]
    if execution_errors:
        findings.append(_finding(
            "probe_execution_error", "low", "high", "confirmed",
            "本地探针执行失败；该失败不是 DNS 协议状态。", execution_errors, [],
            ["检查本地工具可用性，并使用报告中的已审核手工命令。"],
        ))

    nxdomain = by_status.get("NXDOMAIN", [])
    absent_at_authority = {
        item["_qname"] for item in nxdomain
        if item["role"] in {"authoritative", "child_authority"} and item["_qname"]
    }
    nxdomain_by_query: Dict[Tuple[Optional[str], Optional[str]], List[dict]] = {}
    for item in nxdomain:
        nxdomain_by_query.setdefault(_query_identity(item), []).append(item)
    for identity, supporting in nxdomain_by_query.items():
        contradictory = [
            item for item in by_status.get("NOERROR", [])
            if all(identity) and _query_identity(item) == identity
        ]
        if identity[0] in absent_at_authority:
            # NXDOMAIN is about the name, not one record type: the authority has already
            # said it does not exist, so re-asking it proves nothing.
            next_checks = [
                "权威服务器本身也说这个名称不存在，请核对名称拼写、是否漏了域名后缀，"
                "以及它是否只存在于内部 DNS 里。"
            ]
        else:
            next_checks = [
                "向权威服务器复核这个名称是否真的存在，并留意“不存在”这个结果本身也会被缓存一段时间。"
            ]
        findings.append(_finding(
            "name_not_found", "high", "high", "confirmed",
            "查询明确返回“名称不存在”（NXDOMAIN），也就是这个域名在 DNS 里查不到。", supporting,
            contradictory, next_checks,
        ))

    nodata = [
        item for item in by_status.get("NOERROR", [])
        if (item["_answers"] == () and item["_qtype"] is not None
            and not item.get("output_truncated")
            # An unsigned zone has no DS or DNSKEY by design; the DNSSEC
            # assessment reports that, and it is not a missing record.
            and not (item.get("layer") == "dnssec" and item["_qtype"] in {"DS", "DNSKEY"}))
    ]
    nodata_by_query: Dict[Tuple[Optional[str], Optional[str]], List[dict]] = {}
    for item in nodata:
        nodata_by_query.setdefault(_query_identity(item), []).append(item)
    for identity, supporting in nodata_by_query.items():
        contradictory = [
            item for item in observations
            if item not in supporting and all(identity)
            and _query_identity(item) == identity
            and (item["status"] == "NXDOMAIN"
                 or (item["_answers"] is not None and item["_answers"] != ()))
        ]
        qname, qtype = identity
        label = _RECORD_TYPE_LABELS.get(qtype or "", qtype or "该")
        summary = "{0} 这个名字存在，但没有 {1}——服务器明确回答“有这个名字，只是没有这类记录”。".format(
            _safe_text(qname or "该名称"), label,
        )
        siblings = [
            item for item in observations
            if item["_qname"] == qname and item["_qtype"] != qtype and item["_answers"]
        ]
        if siblings:
            # Asking for a type a name never had is a fact, not a fault; say so here so
            # the cause list cannot present it as the reason something is broken.
            summary += "它的其它记录类型都有答案，所以只有当确实需要 {0}时，这才算问题。".format(
                label
            )
        findings.append(_finding(
            "missing_record", "low" if siblings else "medium", "high", "confirmed",
            summary,
            supporting, contradictory,
            ["直接问权威服务器同一类记录，确认这个名字本来是否应该有它。"],
        ))

    servfail = by_status.get("SERVFAIL", [])
    if servfail:
        signature_failed = any(_dnssec_is_bogus(item) for item in observations)
        reachable_authority = any(
            item["role"] in {"authoritative", "child_authority"}
            and item["status"] == "NOERROR" and item["_answers"]
            for item in observations
        )
        if signature_failed and reachable_authority:
            # Reachability and delegation already checked out, and the signature verdict
            # explains the refusal, so neither dead end is worth sending a reader down.
            summary = (
                "有解析器回答“我给不出答案”（SERVFAIL）；权威服务器本身答得上来，"
                "所以这是签名校验没通过导致的拒绝，不是服务器连不上。"
            )
            next_checks = ["按签名校验那一条处理即可；签名修好后 SERVFAIL 会随之消失。"]
        else:
            summary = (
                "有解析器回答“我给不出答案”（SERVFAIL）；单看这一条还判断不出原因，"
                "常见的是权威服务器连不上、委派配置有误，或者防篡改签名（DNSSEC）没通过校验。"
            )
            next_checks = ["确认权威服务器是否可达、委派配置是否正确，以及是不是签名校验失败导致的。"]
        findings.append(_finding(
            "resolver_failure", "high", "high", "confirmed", summary, servfail, [],
            next_checks,
        ))

    refused = [item for item in by_status.get("REFUSED", []) if item["role"] != "authoritative"]
    refused_authoritative = [
        item for item in by_status.get("REFUSED", []) if item["role"] == "authoritative"
    ]
    if refused_authoritative:
        findings.append(_finding(
            "authoritative_server_refused", "low", "low", "unverified",
            "直接询问权威服务器时被拒绝；可能是该服务器不为此区服务（lame），"
            "也可能是此前解析到的服务器地址已过期。", refused_authoritative, [],
            ["重新查询该区的 NS 记录与对应地址，再逐台直接询问。"],
        ))
    if refused:
        findings.append(_finding(
            "query_refused", "medium", "high", "confirmed",
            "服务器明确拒绝了这次查询（REFUSED）：它不愿意为这个来源或这个名字作答。", refused, [],
            ["确认这台解析器是否允许你所在网段查询，以及它是否负责这个域名。"],
        ))

    bogus = [item for item in observations if _dnssec_is_bogus(item)]
    bogus_by_query: Dict[Tuple[Optional[str], Optional[str]], List[dict]] = {}
    for item in bogus:
        bogus_by_query.setdefault(_query_identity(item), []).append(item)
    for identity, supporting in bogus_by_query.items():
        contradictory = [
            item for item in observations
            if item not in supporting and item["status"] == "NOERROR"
            and all(identity) and _query_identity(item) == identity
        ]
        findings.append(_finding(
            "dnssec_validation_failure", "high", "high", "confirmed",
            "这个域名的防篡改签名没有通过校验（DNSSEC bogus）：会校验签名的解析器会因此直接"
            "拒绝给出地址，用户看到的就是“打不开”。原因可能是签名过期、密钥换了没同步，"
            "也可能是应答在路上被改过。", supporting,
            contradictory,
            ["核对签名链是否完整（DS、DNSKEY、RRSIG 三者要对得上）、签名有没有过期，"
             "以及做校验那台机器的时钟是否准确。"],
        ))

    findings.extend(_dnssec_findings(evidence, observations, bool(bogus)))
    findings.extend(_public_resolver_findings(observations))

    loops = [item for item in observations if _has_cname_loop(item)]
    if loops:
        findings.append(_finding(
            "cname_loop", "high", "high", "confirmed",
            "CNAME 链出现重复名称，形成循环。", loops, [],
            ["修正权威区域中的 CNAME 指向并清理缓存。"],
        ))

    parent = [item for item in observations if item["role"] == "parent_delegation" and _nameservers(item) is not None]
    child = [item for item in observations if item["role"] in {"child_authority", "authoritative"} and _nameservers(item) is not None]
    delegation_support = []
    for parent_item in parent:
        for child_item in child:
            if (parent_item["_qname"] is not None
                    and parent_item["_qname"] == child_item["_qname"]
                    and _nameservers(parent_item) != _nameservers(child_item)):
                delegation_support.extend([parent_item, child_item])
    if delegation_support:
        findings.append(_finding(
            "delegation_inconsistency", "high", "high", "confirmed",
            "父区委派与子区公布的名称服务器集合不一致。", delegation_support, [],
            ["分别查询父区和每台子区权威服务器，并核对 glue 记录。"],
        ))

    authoritative = [
        item for item in observations
        if item["role"] == "authoritative" and item["_answers"] is not None
        and _delivered_query_type(item)
    ]
    recursive = [
        item for item in observations
        if item["role"] == "recursive" and item["_answers"] is not None
        # A validating resolver that answered SERVFAIL carries no answer to compare;
        # holding its empty result against the authoritative one would report a
        # disagreement when the real fact is a refused validation, already its own finding.
        and _delivered_query_type(item)
    ]
    recursive_authoritative: Dict[Tuple[str, str, str], Dict[str, List[dict]]] = {}
    for rec in recursive:
        if not _has_known_query_identity(rec):
            continue
        # An unlabelled viewpoint is still one viewpoint: this machine.
        key = (rec["_qname"], rec["_qtype"], rec["vantage"] or "local")
        recursive_authoritative.setdefault(key, {"recursive": [], "authoritative": []})["recursive"].append(rec)
    for auth in authoritative:
        if not _has_known_query_identity(auth):
            continue
        key = (auth["_qname"], auth["_qtype"], auth["vantage"] or "local")
        recursive_authoritative.setdefault(key, {"recursive": [], "authoritative": []})["authoritative"].append(auth)
    for cohort in recursive_authoritative.values():
        if not cohort["recursive"] or not cohort["authoritative"]:
            continue
        unmatched = [
            rec for rec in cohort["recursive"]
            if not any(auth["_answers"] == rec["_answers"] for auth in cohort["authoritative"])
        ]
        matching_recursive = [
            rec for rec in cohort["recursive"]
            if any(auth["_answers"] == rec["_answers"] for auth in cohort["authoritative"])
        ]
        # Separate an unexpired cache from a real disagreement before judging severity:
        # an older serial for the same zone is how caching looks, and reporting it as
        # divergence turns the whole report's headline into a suspicion of tampering.
        stale = [rec for rec in unmatched if _is_stale_soa_copy(rec, cohort["authoritative"])]
        stale_ids = {id(rec) for rec in stale}
        divergent_recursive = [rec for rec in unmatched if id(rec) not in stale_ids]
        if stale:
            resolvers = "、".join(sorted({
                _resolver_text(rec["resolver"]) for rec in stale if rec["resolver"]
            }))
            findings.append(_finding(
                "stale_cached_answer", "low", "high", "confirmed",
                "{0} 缓存的区域信息还是旧版本——它给出的序列号比权威服务器的低，"
                "说明这条缓存还没到期；内容仍来自这个域名的所有者，不是被换掉的答案，"
                "缓存过期后会自动跟上。".format(resolvers or "某台解析器"),
                stale + cohort["authoritative"], [],
                ["等这条记录的缓存时间（TTL）到期后再问同一台解析器，核对序列号是否追平。"],
            ))
        if not divergent_recursive:
            # With every recursive copy stale there is no resolver left whose answer
            # matched, so there is nothing to call agreement; the stale finding stands alone.
            if matching_recursive:
                findings.append(_finding(
                    "authoritative_agreement", "info", "high", "confirmed",
                    "直接询问 {0} 台权威服务器，答案与这台机器解析到的完全相同。".format(
                        len(cohort["authoritative"]),
                    ),
                    cohort["authoritative"] + matching_recursive, [], [],
                ))
            continue
        findings.append(_finding(
            "resolver_authoritative_divergence", "high", "medium", "high_probability",
            "解析器给出的答案与直接问权威服务器的答案不一致；权威服务器的答案更可信，但还要排除缓存和按地区返回不同 IP 的可能。",
            divergent_recursive + cohort["authoritative"], matching_recursive,
            ["在同一个观测点分别再问解析器和权威服务器，并记下缓存时间（TTL）。"],
        ))

    transport_mismatches = []
    injection_support = []
    truncation_support = [
        item for item in observations
        if item["transport"] == "udp" and _is_truncated(item)
    ]
    for index, left in enumerate(observations):
        for right in observations[index + 1:]:
            if not _same_transport_cohort(left, right):
                continue
            if {left["transport"], right["transport"]} != {"tcp", "udp"}:
                continue
            udp = left if left["transport"] == "udp" else right
            tcp = right if udp is left else left
            if _is_truncated(udp):
                truncation_support.extend([udp, tcp])
            if (udp["_answers"] is not None and tcp["_answers"] is not None
                    and udp["_answers"] != tcp["_answers"]):
                transport_mismatches.extend([udp, tcp])
                corroborating = [
                    item for item in observations
                    if item not in (udp, tcp) and item["_answers"] == tcp["_answers"]
                    and _same_query(item, tcp)
                    and (item["vantage"] != udp["vantage"] or item["role"] == "authoritative")
                ]
                if corroborating:
                    injection_support.extend([udp, tcp] + corroborating)

    edns_clues = []
    for item in observations:
        edns = item.get("edns")
        if isinstance(edns, dict) and any(edns.get(key) for key in ("error", "failure", "fallback")):
            edns_clues.append(item)
        elif _normalized_status(item.get("edns_status")) in {"FORMERR", "BADVERS", "NOTIMP"}:
            edns_clues.append(item)
    if transport_mismatches:
        findings.append(_finding(
            "transport_answer_divergence", "high", "medium", "high_probability",
            "同一个观测点、同一个解析器上，UDP 和 TCP 拿到的答案不一样。", transport_mismatches, [],
            ["在相同网络重复抓取 TCP 与 UDP 查询，核对请求 ID、源端口和响应来源。"],
        ))
    if injection_support:
        findings.append(_finding(
            "suspected_dns_injection", "high", "medium", "high_probability",
            "UDP 答案偏离 TCP，且 TCP 得到独立观测支持；这符合注入线索但尚不能确证。",
            injection_support, [],
            ["进行受控抓包并从另一网络复测，确认异常响应的来源和时序。"],
        ))
    if truncation_support or edns_clues:
        findings.append(_finding(
            "truncation_or_edns_issue", "medium", "medium", "high_probability",
            "存在 UDP 截断或 EDNS 降级/失败线索，TCP 结果应作为复核依据。",
            truncation_support + edns_clues, [],
            ["比较启用/禁用 EDNS 的 UDP 查询，并确认 TCP 回退是否成功。"],
        ))

    findings.extend(_private_answer_findings(evidence, observations))

    regional_requested = _regional_analysis_requested(evidence, observations)
    regional_semantics = _regional_semantics(observations)
    regional_support = regional_semantics["divergent_support"]
    if regional_support:
        findings.append(_finding(
            "regional_answer_divergence", "medium", "high", "confirmed",
            "至少两个不同观测点拿到不同答案；这只能说明按地区返回的结果不同，不能说明被劫持。",
            regional_support, [],
            ["核对按地区分配（GeoDNS/CDN）的策略，并在各观测点直接问权威服务器。"],
        ))
        findings.append(_finding(
            "geodns_behavior", "low", "low", "unverified",
            "每个观测点内部答案一致、观测点之间不同，但还没有独立证据能区分按地区分配、解析器行为和人为操纵。",
            regional_support, [],
            ["向 DNS/CDN 配置负责人确认地域路由策略和 Anycast 发布范围。"],
        ))
    elif regional_semantics["unstable_divergence"]:
        findings.append(_finding(
            "regional_comparison_inconclusive", "low", "low", "unverified",
            "答案确有差异，但每个观测点内部就不一致，不能确认这是地区差异。",
            [item for item in observations if item["_answers"] is not None], [],
            ["在每个观测点用同一个解析器、同一种传输方式重复查询，再比较稳定下来的答案。"],
        ))
    elif regional_requested and not regional_semantics["comparable_support"]:
        findings.append(_finding(
            "insufficient_regional_evidence", "low", "low", "unverified",
            "缺少来自两个明确观测点、同一问题、同样条件且时间相近的可比结果，无法就地区差异下结论。", observations, [],
            ["至少再从另一个标注清楚的观测点，用可比的解析器和传输方式，在十分钟内重复一次。"],
        ))

    if not findings:
        findings.append(_finding(
            "insufficient_evidence", "low", "low", "unverified",
            "现有观测没有满足任何确定性分类条件。", observations, [],
            ["补齐响应状态、答案内容、解析器、传输方式、观测点，以及对权威服务器的查询。"],
        ))
    return findings


def _safe_text(value: Any) -> str:
    if isinstance(value, str):
        return redact_text(value)
    return redact_text(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _citation(finding: dict) -> str:
    """Plain-language weight of evidence; the probe ids stay in the JSON."""
    supporting = len(finding.get("supporting_probe_ids", []) or ())
    contradictory = len(finding.get("contradictory_probe_ids", []) or ())
    if supporting:
        text = "{0} 次查询记录到这一现象".format(supporting)
    else:
        text = "没有直接的查询记录支持这一条"
    if contradictory:
        text += "，另有 {0} 次查询的结果与之相反".format(contradictory)
    return text


def _observation_layer(item: dict) -> str:
    layer = item.get("layer")
    return layer if isinstance(layer, str) and layer in _LAYER_TITLES else "local"


def _finding_layers(finding: dict, probe_layers: Dict[str, str]) -> List[str]:
    category = finding.get("category")
    if category in _CATEGORY_LAYERS:
        return [_CATEGORY_LAYERS[category]]
    layers = []
    for probe_id in finding.get("supporting_probe_ids", []):
        layer = probe_layers.get(probe_id, "local")
        if layer not in layers:
            layers.append(layer)
    return layers or ["local"]


def _addresses_by_family(observations: List[dict]) -> Tuple[List[str], List[str]]:
    ipv4: List[str] = []
    ipv6: List[str] = []
    for item in observations:
        for answer in item["_answers"] or ():
            for value in answer:
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                bucket = ipv4 if address.version == 4 else ipv6
                text = str(address)
                if text not in bucket:
                    bucket.append(text)
    return ipv4, ipv6


def _alias_chain(observations: List[dict]) -> List[str]:
    for item in observations:
        chain = item.get("cname_chain")
        if isinstance(chain, (list, tuple)) and len(chain) >= 2:
            return [str(value) for value in chain]
    return []


def _numeric_ttls(observations: List[dict]) -> List[int]:
    values = []
    for item in observations:
        for ttl in item["_ttls"] or ():
            if isinstance(ttl, int) and ttl not in values:
                values.append(ttl)
    return sorted(values)


def _durations_ms(observations: List[dict]) -> List[int]:
    values = []
    for item in observations:
        duration = item.get("duration_ms")
        if isinstance(duration, (int, float)):
            values.append(int(duration))
    return sorted(values)


def _vantage_labels(observations: List[dict]) -> List[str]:
    labels = []
    for item in observations:
        label = item.get("vantage")
        if label and label not in labels:
            labels.append(label)
    return labels


def _trace_chain(observations: List[dict]) -> List[str]:
    for item in observations:
        chain = item.get("delegation_chain")
        if isinstance(chain, (list, tuple)) and chain:
            hops: List[str] = []
            for value in chain:
                text = "根" if str(value) == "." else str(value)
                # The final answer repeats the zone it was answered from.
                if not hops or hops[-1] != text:
                    hops.append(text)
            return hops
    return []


def _execution_note(item: dict) -> Optional[str]:
    if item.get("timed_out"):
        return "超时未收到应答（timeout）"
    if item.get("error"):
        return "命令未能执行"
    returncode = item.get("returncode")
    if returncode not in {0, None}:
        return "命令以退出码 {0} 结束，属于运行异常".format(returncode)
    return None


def _sentence(text: Any) -> str:
    """First sentence of a finding summary, for a table cell."""
    value = _safe_text(text).strip()
    for separator in ("。", "；"):
        if separator in value:
            value = value.split(separator)[0]
            break
    return value.strip("。； ")


_LAYER_TITLES = {
    "local": "这台机器的 DNS",
    "dnssec": "防篡改签名（DNSSEC）",
    "public": "换公共 DNS 再问",
    "trace": "从根服务器逐级追查",
    "authoritative": "直接问权威服务器",
    "regional": "别的地区问到什么",
}
_LAYER_ORDER = ("local", "dnssec", "public", "trace", "authoritative", "regional")
_OK_LABELS = {
    "local": "已确认正常",
    "dnssec": "已确认正常",
    "public": "已确认一致",
    "trace": "已确认通畅",
    "authoritative": "已确认一致",
    "regional": "已确认一致",
}
# Categories that describe a healthy or merely undecided state; none of them may be
# printed as a cause of failure.
_POSITIVE_CATEGORIES = frozenset({
    "resolution_succeeded", "dnssec_valid", "dnssec_unsigned",
    "public_resolver_agreement", "authoritative_agreement",
})
_NON_CAUSE_CATEGORIES = _POSITIVE_CATEGORIES | frozenset({
    "no_evidence", "insufficient_evidence", "insufficient_regional_evidence",
    "regional_comparison_inconclusive", "public_resolver_divergence",
    "dnssec_indeterminate", "geodns_behavior",
})
# Neither a pass nor a fault: the check ran but cannot settle the question, so its row
# must not be printed as a clean result.
_INCONCLUSIVE_CATEGORIES = _NON_CAUSE_CATEGORIES - _POSITIVE_CATEGORIES
# Findings that belong to one layer by meaning, whatever probes support them.
_CATEGORY_LAYERS = {
    "dnssec_validation_failure": "dnssec", "dnssec_unsigned": "dnssec",
    "dnssec_valid": "dnssec", "dnssec_indeterminate": "dnssec",
    "delegation_inconsistency": "trace",
    "resolver_authoritative_divergence": "authoritative",
    "stale_cached_answer": "authoritative",
    "authoritative_server_refused": "authoritative",
    "authoritative_agreement": "authoritative",
    "public_resolver_agreement": "public", "public_resolver_divergence": "public",
    "regional_answer_divergence": "regional", "geodns_behavior": "regional",
    "regional_comparison_inconclusive": "regional",
    "insufficient_regional_evidence": "regional",
}
_STATUS_MEANINGS = {
    "NOERROR": "查询成功",
    "NXDOMAIN": "名称不存在",
    "NODATA": "名称存在但没有这类记录",
    "SERVFAIL": "解析器无法给出答案",
    "REFUSED": "服务器拒绝回答",
    "FORMERR": "服务器认为请求格式有误",
}


# How much a problem explains, most explanatory first. A row or headline that picks the
# first finding it happens to see would announce a missing AAAA record ahead of a failed
# signature check.
_SEVERITY_ORDER = (
    "suspected_dns_injection",
    "dnssec_validation_failure",
    "cname_loop",
    "delegation_inconsistency",
    "resolver_authoritative_divergence",
    "authoritative_server_refused",
    "regional_answer_divergence",
    "private_address_answer",
    "transport_answer_divergence",
    "truncation_or_edns_issue",
    "resolver_failure",
    "query_refused",
    "query_timeout",
    "probe_execution_error",
    "name_not_found",
    "missing_record",
    "stale_cached_answer",
)


def _severity_rank(finding: dict) -> int:
    category = finding.get("category")
    if category in _SEVERITY_ORDER:
        return _SEVERITY_ORDER.index(category)
    return len(_SEVERITY_ORDER)


def _by_severity(findings: List[dict]) -> List[dict]:
    return sorted(findings, key=_severity_rank)


def _dnssec_row(assessment: dict, row_findings: List[dict]) -> Tuple[str, str, str]:
    validation = assessment.get("validation")
    note = _safe_text(assessment.get("reason") or "")
    if validation == "bogus":
        return "❌", "已确认有问题", note or "签名校验没有通过"
    if validation == "secure":
        return "✅", "已确认正常", note or "签名有效且通过校验"
    if validation == "insecure":
        return "⚪", "不适用", note or "这个域名没有启用签名，所以无从校验"
    return "❓", "待验证", note or _sentence(
        row_findings[0].get("summary") if row_findings else "证据不足以判断"
    )


def _layer_row(
    layer: str,
    row_findings: List[dict],
    row_observations: List[dict],
    evidence: dict,
) -> Tuple[str, str, str]:
    """Icon, verdict, and one plain-language note for a single check row."""
    assessment = evidence.get("dnssec")
    if layer == "dnssec" and isinstance(assessment, dict):
        return _dnssec_row(assessment, row_findings)
    problems = [
        item for item in row_findings
        if item.get("category") not in _NON_CAUSE_CATEGORIES
    ]
    positives = [item for item in row_findings if item.get("category") in _POSITIVE_CATEGORIES]
    inconclusive = [
        item for item in row_findings
        if item.get("category") in _INCONCLUSIVE_CATEGORIES
    ]
    # A low-severity fact — a name that simply never had the record type we asked for —
    # must not blacken a row whose real question was answered. It belongs in the note.
    minor = _by_severity([item for item in problems if item.get("severity") == "low"])
    deciding = [item for item in problems if item.get("severity") != "low"]
    confirmed = _by_severity([item for item in deciding if item.get("status") == "confirmed"])
    probable = _by_severity(
        [item for item in deciding if item.get("status") == "high_probability"]
    )
    if confirmed:
        return "❌", "已确认有问题", _sentence(confirmed[0].get("summary"))
    if probable:
        return "⚠️", "高概率有问题", _sentence(probable[0].get("summary"))
    note = _layer_note(layer, row_observations, row_findings)
    if not row_observations:
        return "⚪", "未执行", note or "本次没有做这项检查"
    if inconclusive:
        return "❓", "待验证", note or _sentence(inconclusive[0].get("summary"))
    if positives:
        return "✅", _OK_LABELS[layer], _with_aside(note, minor)
    if minor:
        return "❓", "待验证", _sentence(minor[0].get("summary"))
    if problems:
        return "❓", "待验证", _sentence(problems[0].get("summary"))
    return "❓", "待验证", note or "查询已完成，但证据还不足以给出结论"


def _with_aside(note: str, minor: List[dict]) -> str:
    """Keep a passing row passing while still stating the minor fact behind it."""
    if not minor:
        return note
    # Only the leading clause: the full sentence explains itself in 问题出在哪 already.
    aside = _sentence(minor[0].get("summary")).split("——")[0].rstrip("。")
    return "；".join(part for part in (note, aside) if part)


def _layer_note(layer: str, observations: List[dict], row_findings: List[dict]) -> str:
    if layer == "local":
        ipv4, ipv6 = _addresses_by_family(observations)
        parts = []
        if ipv4 or ipv6:
            parts.append("拿到 {0} 个 IPv4、{1} 个 IPv6 地址".format(len(ipv4), len(ipv6)))
        # Compare per record type: one set across A/AAAA/NS/SOA would always differ.
        by_type: Dict[str, Dict[str, set]] = {}
        for item in observations:
            if not item["_answers"] or not item["_qtype"]:
                continue
            bucket = by_type.setdefault(item["_qtype"], {})
            bucket.setdefault(item["transport"] or "", set()).add(item["_answers"])
        compared = [
            value for value in by_type.values() if {"udp", "tcp"} <= set(value)
        ]
        if compared:
            same = all(value["udp"] == value["tcp"] for value in compared)
            parts.append("UDP 和 TCP 结果一致" if same else "UDP 与 TCP 结果不同")
        return "，".join(parts)
    if layer == "public":
        resolvers = sorted({
            item["resolver"] for item in observations
            if item["resolver"] and item["resolver"] != "system"
        })
        if not resolvers:
            return ""
        categories = {item.get("category") for item in row_findings}
        if "public_resolver_divergence" in categories:
            # Which record type actually differed decides the wording: calling an SOA
            # serial difference "地址不完全相同" describes something that did not happen.
            by_type: Dict[str, set] = {}
            for item in observations:
                if not item["_qtype"] or item["_answers"] is None:
                    continue
                by_type.setdefault(item["_qtype"], set()).add(item["_answers"])
            differing = sorted(
                qtype for qtype, values in by_type.items() if len(values) > 1
            )
            if not differing or {"A", "AAAA"} & set(differing):
                outcome = "给出的地址不完全相同，常见于 CDN 或按地区解析，单凭这一点判断不了异常"
            else:
                outcome = (
                    "给出的 {0} 记录不完全相同，多为各家缓存的版本新旧不同，"
                    "单凭这一点判断不了异常".format("、".join(differing))
                )
        elif "public_resolver_agreement" in categories:
            outcome = "返回同一批地址"
        else:
            outcome = "均有应答"
        return "{0} {1}".format("、".join(resolvers), outcome)
    if layer == "trace":
        chain = _trace_chain(observations)
        if not chain:
            return ""
        if any(item["status"] == "NOERROR" for item in observations):
            return "{0}，每一跳都正常应答".format(" → ".join(chain))
        if len(chain) == 1:
            return "根服务器没有给出下一级委派，这个后缀在公网 DNS 里不存在"
        return "{0}，到这里就没有再往下的委派".format(" → ".join(chain))
    if layer == "authoritative":
        direct = [
            item for item in observations
            if item["role"] in {"authoritative", "child_authority", "parent_delegation"}
        ]
        answered = [item for item in direct if item["_answers"] and not _execution_note(item)]
        unreachable = sorted({
            item["resolver"] for item in direct
            if item["resolver"] and _execution_note(item)
        })
        servers = sorted({item["resolver"] for item in answered if item["resolver"]})
        # A server that answered one query and failed another is not an unreachable one.
        unreachable = [item for item in unreachable if item not in servers]
        if not servers:
            if unreachable:
                return "{0} 台权威服务器都没有应答".format(len(unreachable))
            return ""
        digests = {_answer_digest([item]) for item in answered if item["role"] == "authoritative"}
        note = "直接问了 {0} 台权威服务器".format(len(servers))
        if len(digests) == 1:
            note += "，答案一致：{0}".format(digests.pop())
        if unreachable:
            note += "；另有 {0} 台没有应答".format(len(unreachable))
        return note
    if layer == "regional":
        labels = [_vantage_text(label) for label in _vantage_labels(observations)]
        if len(labels) >= 2:
            # Same wording and casing as the regional table below: the row should say
            # what the comparison found, not just which points took part in it.
            digests = {_answer_digest([item]) for item in observations if item["_answers"]}
            joined = "、".join(sorted(labels))
            if len(digests) == 1:
                return "{0} 问到的地址相同：{1}".format(joined, digests.pop())
            return "{0} 问到的地址不完全相同".format(joined)
        if labels:
            return "只有 {0} 一个观测点，没有第二个点可以互相比对".format(labels[0])
    return ""


def _ttls_by_kind(observations: List[dict]) -> Tuple[List[int], List[int]]:
    """TTLs split into address records and alias (CNAME) records."""
    address: List[int] = []
    alias: List[int] = []
    for item in observations:
        answers = item.get("answers")
        if not isinstance(answers, (list, tuple)):
            continue
        for answer in answers:
            if not isinstance(answer, dict):
                continue
            ttl = answer.get("ttl")
            if not isinstance(ttl, int):
                continue
            record_type = str(answer.get("type") or answer.get("record_type") or "").upper()
            if record_type == "CNAME":
                bucket = alias
            elif record_type in {"A", "AAAA"}:
                # An NS or SOA TTL from the same run says nothing about how long the
                # address answer is cached, so it stays out of both buckets.
                bucket = address
            else:
                continue
            if ttl not in bucket:
                bucket.append(ttl)
    return sorted(address), sorted(alias)


def _ttl_span(values: List[int], label: str = "") -> str:
    if not values:
        return ""
    if values[0] == values[-1]:
        return "{0}约 {1} 秒".format(label, values[0])
    return "{0} {1} 到 {2} 秒".format(label, values[0], values[-1]).strip()


def _answer_lines(observations: List[dict], target_text: str) -> List[str]:
    lines = []
    chain = _alias_chain(observations)
    ipv4, ipv6 = _addresses_by_family(observations)
    if chain:
        lines.append("{0} 是个别名，真正给出地址的是 {1}：".format(
            _safe_text(chain[0]), _safe_text(chain[-1]),
        ))
    elif ipv4 or ipv6:
        lines.append("{0} 解析到的地址：".format(target_text))
    if ipv4:
        lines.append("- IPv4：{0}".format("、".join(_safe_text(item) for item in ipv4)))
    if ipv6:
        lines.append("- IPv6：{0}".format("、".join(_safe_text(item) for item in ipv6)))
    address_ttls, alias_ttls = _ttls_by_kind(observations)
    parts = []
    if address_ttls:
        parts.append(_ttl_span(address_ttls, "地址"))
    if alias_ttls:
        parts.append(_ttl_span(alias_ttls, "别名"))
    if parts:
        lines.append("- 缓存时间：{0}".format("，".join(parts)))
    elif _numeric_ttls(observations):
        lines.append("- 缓存时间：{0}".format(_ttl_span(_numeric_ttls(observations))))
    return lines


def _status_lines(observations: List[dict]) -> List[str]:
    counts: Dict[str, int] = {}
    for item in observations:
        if item["status"]:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
    lines = []
    for status, count in sorted(counts.items()):
        meaning = _STATUS_MEANINGS.get(status)
        lines.append("- 响应状态 {0}（{1}）：{2} 次".format(
            status, meaning or "非标准状态", count,
        ))
    notes: Dict[str, List[str]] = {}
    for item in observations:
        note = _execution_note(item)
        if note:
            notes.setdefault(note, []).append("`{0}`".format(_safe_text(item["id"])))
    for note, ids in notes.items():
        lines.append("- {0}：{1}".format(note, "、".join(ids)))
    durations = _durations_ms(observations)
    if durations:
        lines.append("- 应答耗时：{0}".format(
            "{0} 毫秒".format(durations[0]) if durations[0] == durations[-1]
            else "{0} 到 {1} 毫秒".format(durations[0], durations[-1])
        ))
    return lines


def _alias_only_types(observations: List[dict]) -> List[str]:
    """Query types that came back NOERROR but carried only a CNAME."""
    types = []
    for item in observations:
        if item["status"] != "NOERROR" or not item["_answers"]:
            continue
        if _delivered_query_type(item):
            continue
        qtype = item["_qtype"]
        if qtype and qtype not in types:
            types.append(qtype)
    return types


def _answer_digest(observations: List[dict]) -> str:
    """Readable one-cell summary of what a resolver or server answered."""
    ipv4, ipv6 = _addresses_by_family(observations)
    if ipv4 or ipv6:
        return "、".join(_safe_text(item) for item in ipv4 + ipv6)
    chain = _alias_chain(observations)
    if chain:
        return "只给出别名，指向 {0}".format(_safe_text(chain[-1]).rstrip("."))
    nameservers = []
    for item in observations:
        for answer in item["_answers"] or ():
            if len(answer) >= 3 and answer[1].upper() == "NS":
                text = _safe_text(answer[2]).rstrip(".")
                if text and text not in nameservers:
                    nameservers.append(text)
    if nameservers:
        return "权威服务器：{0}".format("、".join(nameservers))
    statuses = sorted({item["status"] for item in observations if item["status"]})
    if statuses:
        return "没有地址，响应状态 {0}".format("、".join(statuses))
    notes = [note for note in (_execution_note(item) for item in observations) if note]
    if notes:
        return notes[0]
    return "没有可读的答案"


def _comparison_table(observations: List[dict], title: str) -> List[str]:
    """One row per resolver or server, listing what it answered."""
    rows: Dict[str, List[dict]] = {}
    for item in observations:
        rows.setdefault(_resolver_text(item["resolver"]), []).append(item)
    if not rows:
        return []
    lines = ["| {0} | 它给出的答案 |".format(title), "| --- | --- |"]
    for label in sorted(rows):
        lines.append("| {0} | {1} |".format(label, _answer_digest(rows[label])))
    return lines + [""]


def _node_findings(node_observations: List[dict], findings: List[dict]) -> List[dict]:
    ids = {item["id"] for item in node_observations}
    return [
        item for item in findings
        if ids & set(item.get("supporting_probe_ids") or ())
    ]


# A comparison cites both sides, but only one of them is the suspect: the other is the
# yardstick it was measured against. Without this, a resolver disagreeing with the zone
# would put a mark on the authoritative servers that reported the zone correctly.
_FINDING_ACCUSED_ROLES = {
    "resolver_authoritative_divergence": frozenset({"recursive", "local"}),
    "stale_cached_answer": frozenset({"recursive", "local"}),
}


def _finding_accuses(finding: dict, node_observations: List[dict]) -> bool:
    """Whether this finding says something about this hop, rather than merely citing it."""
    roles = _FINDING_ACCUSED_ROLES.get(finding.get("category"))
    if roles is None:
        return True
    cited = set(finding.get("supporting_probe_ids") or ())
    return any(
        item["role"] in roles for item in node_observations if item["id"] in cited
    )


def _node_icon(node_observations: List[dict], findings: List[dict]) -> str:
    """Worst thing the evidence says about one hop, as a single glyph.

    Only what is true of this hop alone. A comparison finding describes a set of
    resolvers, not any one of them, so painting every participant ❓ would light up
    the whole picture for what is usually ordinary CDN variation. NXDOMAIN and
    NODATA are faithful answers: the name's problem is the report's to explain, not
    this hop's fault.
    """
    if not node_observations:
        return "⚪"
    if any(_execution_note(item) for item in node_observations):
        return "❌"
    statuses = {item["status"] for item in node_observations}
    if statuses & {"SERVFAIL", "REFUSED", "FORMERR"}:
        return "❌"
    if any(_unroutable_answers(item) for item in node_observations if _offnet_resolver(item)):
        return "⚠️"
    deciding = [
        item for item in _node_findings(node_observations, findings)
        if item.get("category") not in _NON_CAUSE_CATEGORIES
        and item.get("severity") != "low"
        and _finding_accuses(item, node_observations)
    ]
    if any(item.get("status") == "confirmed" for item in deciding):
        return "❌"
    if any(item.get("status") == "high_probability" for item in deciding):
        return "⚠️"
    if statuses & {"NOERROR", "NXDOMAIN", "NODATA"}:
        return "✅"
    return "❓"


def _address_digest(node_observations: List[dict]) -> str:
    """What this hop handed back, address records first."""
    addressed = [item for item in node_observations if item["_qtype"] in {"A", "AAAA"}]
    digest = _answer_digest(addressed or node_observations)
    unroutable = []
    for item in node_observations:
        for value in _unroutable_answers(item):
            if value in digest and value not in unroutable:
                unroutable.append(value)
    if unroutable:
        digest += "（内网地址，公网到不了）"
    return digest


def _node_line(
    label: str,
    node_observations: List[dict],
    findings: List[dict],
    marks: Dict[str, List[str]],
) -> str:
    icon = _node_icon(node_observations, findings)
    detail = _address_digest(node_observations) if node_observations else "本次没有检查"
    if icon in marks:
        marks[icon].append("{0}：{1}".format(label, detail))
    return "{0} {1}　{2}".format(label, icon, detail)


def _hop_chain(observations: List[dict]) -> List[dict]:
    """The longest recorded root-downward walk; several types trace the same path."""
    best: List[dict] = []
    for item in observations:
        if _observation_layer(item) != "trace":
            continue
        hops = [hop for hop in item.get("hops") or () if isinstance(hop, dict)]
        if len(hops) > len(best):
            best = hops
    return best


def _hop_text(hop: dict, icon: str = "✅") -> str:
    zone = str(hop.get("zone") or "")
    label = "根服务器" if zone == "." else _safe_text(zone)
    nameservers = [
        _safe_text(value).rstrip(".") for value in hop.get("nameservers") or ()
    ]
    parts = []
    if len(nameservers) > 3:
        parts.append("交给 {0} 台服务器".format(len(nameservers)))
    elif nameservers:
        parts.append("交给 {0}".format("、".join(nameservers)))
    rtt = hop.get("rtt_ms")
    if isinstance(rtt, (int, float)):
        parts.append("{0} 毫秒".format(int(rtt)))
    return "{0} {1}　{2}".format(label, icon, "，".join(parts) or "有应答")


def _tree_block(branches: List[List[str]], spaced: bool = False) -> List[str]:
    """Join rendered branch blocks under one parent with box-drawing glyphs."""
    lines: List[str] = []
    blocks = [block for block in branches if block]
    for index, block in enumerate(blocks):
        last = index == len(blocks) - 1
        lines.append("{0}─ {1}".format("└" if last else "├", block[0]))
        for line in block[1:]:
            lines.append(("   " if last else "│  ") + line)
        if spaced and not last:
            lines.append("│")
    return lines


def _authority_branch(
    observations: List[dict],
    findings: List[dict],
    marks: Dict[str, List[str]],
) -> List[str]:
    """Root → TLD → zone → the servers that answer for it."""
    hops = _hop_chain(observations)
    servers: Dict[str, List[dict]] = {}
    for item in observations:
        if (_observation_layer(item) == "authoritative"
                and item["role"] in {"authoritative", "child_authority"}
                and item["resolver"]):
            servers.setdefault(item["resolver"], []).append(item)
    if not hops and not servers:
        return []
    block = ["权威服务器一侧（绕过缓存，从根往下问）"]
    walk = [hop for hop in hops if hop.get("zone")]
    # A trace that stops early is the delegation problem; the glyph belongs on the last
    # zone it reached, not on every hop that answered before it.
    trace_icon = _node_icon(
        [item for item in observations if _observation_layer(item) == "trace"], findings,
    )
    for depth, hop in enumerate(walk):
        last_hop = depth == len(walk) - 1
        icon = trace_icon if last_hop and trace_icon != "✅" else "✅"
        text = _hop_text(hop, icon)
        if last_hop and icon in marks:
            marks[icon].append(text.split(" ")[0])
        block.append("   " * depth + ("└─ " if depth else "") + text)
    leaves = [
        [_node_line(_resolver_text(resolver), servers[resolver], findings, marks)]
        for resolver in sorted(servers)
    ]
    if leaves:
        indent = "   " * len(walk)
        block.extend(indent + line for line in _tree_block(leaves))
    return block


def _recursive_answer_note(node_groups: List[List[dict]]) -> str:
    """Say it in words when the recursive hops did not all hand back the same addresses.

    The glyphs stay clean because differing addresses are not a per-hop fault; this
    line keeps the fact visible instead of hiding it behind a row of ❓.
    """
    seen = []
    for group in node_groups:
        addressed = [item for item in group if item["_qtype"] in {"A", "AAAA"}]
        ipv4, ipv6 = _addresses_by_family(addressed)
        digest = frozenset(ipv4 + ipv6)
        if digest and digest not in seen:
            seen.append(digest)
    if len(seen) < 2:
        return ""
    return (
        "上面几个解析器给出的地址不完全相同。大站点按地区分配入口时本来就会这样，"
        "不等于被篡改；具体差异见下面的对比表。"
    )


def _topology_section(
    evidence: dict,
    observations: List[dict],
    findings: List[dict],
    target_text: str,
) -> List[str]:
    """One picture of every hop a request passes through, worst hops marked."""
    marks: Dict[str, List[str]] = {"❌": [], "⚠️": [], "❓": []}
    local: List[dict] = []
    public: Dict[str, List[dict]] = {}
    regional: Dict[str, List[dict]] = {}
    for item in observations:
        layer = _observation_layer(item)
        if item.get("vantage"):
            regional.setdefault(item["vantage"], []).append(item)
        elif layer in {"local", "dnssec"} and item["resolver"] in {None, "system"}:
            local.append(item)
        elif layer in {"public", "dnssec"} and item["resolver"]:
            public.setdefault(item["resolver"], []).append(item)

    branches: List[List[str]] = []
    if local:
        addresses = []
        for item in local:
            for value in item.get("resolver_addresses") or ():
                text = _safe_text(value)
                if text not in addresses:
                    addresses.append(text)
        label = "本机默认解析器"
        if addresses:
            label += "（{0}）".format(
                addresses[0] if len(addresses) == 1
                else "{0} 等 {1} 个".format(addresses[0], len(addresses))
            )
        branches.append([_node_line(label, local, findings, marks)])
    if public:
        branches.append(["公共 DNS"] + _tree_block([
            [_node_line(_resolver_text(resolver), public[resolver], findings, marks)]
            for resolver in sorted(public)
        ]))
    if regional:
        branches.append(["别的地区的解析器（异地观测）"] + _tree_block([
            [_node_line(_vantage_text(label), regional[label], findings, marks)]
            for label in sorted(regional)
        ]))
    authority = _authority_branch(observations, findings, marks)
    if authority:
        branches.append(authority)
    if not branches:
        return []

    lines = [
        "## 解析链路图",
        "",
        "```text",
        "[你的电脑]　查 {0}".format(target_text),
        "│",
    ]
    lines.extend(_tree_block(branches, spaced=True))
    lines.extend([
        "```",
        "",
        "> 节点含义：✅ 正常　❌ 已确认有问题　⚠️ 可能有问题　❓ 待验证　⚪ 未检查",
        "",
    ])
    flagged = marks["❌"] + marks["⚠️"]
    if flagged:
        lines.append("**要看的节点**")
        lines.append("")
        lines.extend("- {0}".format(text) for text in flagged)
        lines.append("")
    elif marks["❓"]:
        lines.append("没有节点被判定为有问题。")
        lines.append("")
    else:
        lines.append("从这台机器到权威服务器，每一跳都正常应答，没有发现异常节点。")
        lines.append("")
    if marks["❓"]:
        # A row that never reached a verdict must not be read as one of the healthy ones.
        lines.append("还没能得出结论的节点：{0}。".format("、".join(
            text.split("：")[0] for text in marks["❓"]
        )))
        lines.append("")
    note = _recursive_answer_note(
        ([local] if local else [])
        + [public[key] for key in sorted(public)]
        + [regional[key] for key in sorted(regional)]
    )
    if note:
        lines.append(note)
        lines.append("")
    return lines


def _observed_section(
    evidence: dict,
    observations: List[dict],
    findings: List[dict],
    target_text: str,
) -> List[str]:
    lines = ["## 查到了什么", ""]
    by_layer: Dict[str, List[dict]] = {}
    for item in observations:
        by_layer.setdefault(_observation_layer(item), []).append(item)

    answers = _answer_lines(by_layer.get("local") or observations, target_text)
    if answers:
        lines.extend(["**这个域名指向哪里**", ""] + answers + [""])

    status_lines = _status_lines(observations)
    if status_lines:
        lines.extend(["**每次查询的结果**", ""] + status_lines + [""])

    caveats = []
    # Only the local layer: an authoritative server answering with a bare referral
    # CNAME is a different situation and is explained in its own section.
    alias_only = _alias_only_types(by_layer.get("local") or [])
    if alias_only:
        # The old report called these "stable non-empty answers", which reads as a pass
        # the query never earned; say plainly why an alias has no records of its own.
        caveats.append(
            "- 查 {0} 时只返回了别名（CNAME）、没有 {0} 记录本身，"
            "这对指向别名的名称是正常的：这类记录只登记在别名指向的那一级上。".format(
                "、".join(alias_only)
            )
        )
    if caveats:
        lines.extend(["**容易误会的地方**", ""] + caveats + [""])

    assessment = evidence.get("dnssec")
    if isinstance(assessment, dict) and assessment.get("reason"):
        lines.extend([
            "**防篡改签名（DNSSEC）**",
            "",
            "- {0}".format(_sentence(assessment.get("reason")) + "。"),
            "",
        ])

    if by_layer.get("public"):
        lines.extend(["**换公共 DNS 再问**", ""])
        lines.extend(_comparison_table(by_layer["public"], "公共 DNS"))

    trace_chain = _trace_chain(by_layer.get("trace") or observations)
    if trace_chain:
        lines.extend([
            "**从根服务器逐级追查**",
            "",
            "- 委派链路：{0}".format(" → ".join(_safe_text(hop) for hop in trace_chain)),
            "",
        ])

    if by_layer.get("authoritative"):
        # The step that looks up each nameserver's own address belongs to the setup,
        # not to the comparison, so keep it out of the table.
        direct = [
            item for item in by_layer["authoritative"]
            if item["role"] in {"authoritative", "child_authority", "parent_delegation"}
        ]
        if direct:
            lines.extend(["**直接问权威服务器**", ""])
            lines.extend(_comparison_table(direct, "权威服务器"))

    regional = [item for item in observations if item.get("vantage")]
    if len(_vantage_labels(regional)) >= 2:
        grouped: Dict[str, List[dict]] = {}
        for item in regional:
            grouped.setdefault(_vantage_text(item["vantage"]), []).append(item)
        lines.extend(["**别的地区问到什么**", "", "| 观测点 | 它给出的答案 |", "| --- | --- |"])
        for label in sorted(grouped):
            # Same digest as the resolver tables: a reader should not have to learn a
            # second way of reading an answer just because it came from far away.
            lines.append("| {0} | {1} |".format(label, _answer_digest(grouped[label])))
        lines.append("")
    return lines


def _cause_section(findings: List[dict]) -> List[str]:
    """Rendered only when a real problem was observed; success is never a cause."""
    causes = [
        item for item in findings
        if item.get("category") not in _NON_CAUSE_CATEGORIES
        and item.get("status") in {"confirmed", "high_probability"}
    ]
    if not causes:
        return []
    icons = {"confirmed": "❌", "high_probability": "⚠️"}
    lines = ["## 问题出在哪", ""]
    seen: List[str] = []
    # Low severity means "true, but it explains nothing by itself". Printing it with the
    # same ❌ as a failed signature check would make the two look equally serious.
    minor = [item for item in causes if item.get("severity") == "low"]
    deciding = [item for item in causes if item.get("severity") != "low"]
    for item in _by_severity(deciding):
        summary = _safe_text(item.get("summary", ""))
        if summary in seen:
            # Several probes can report the same fault; say it once.
            continue
        seen.append(summary)
        lines.append("- {0} {1}".format(icons.get(item.get("status"), "❓"), summary))
        lines.append("  - 依据：{0}".format(_citation(item)))
    if minor:
        if deciding:
            lines.append("")
        lines.append("次要发现（一般不影响正常使用）：")
        lines.append("")
        for item in _by_severity(minor):
            summary = _safe_text(item.get("summary", ""))
            if summary in seen:
                continue
            seen.append(summary)
            lines.append("- {0}".format(summary))
            lines.append("  - 依据：{0}".format(_citation(item)))
    lines.append("")
    return lines


def _conclusion(
    findings: List[dict],
    target_text: str,
    pending_rows: int = 0,
    has_address: bool = True,
) -> str:
    """One sentence a non-specialist can act on, never stronger than the evidence."""
    causes = [
        item for item in findings if item.get("category") not in _NON_CAUSE_CATEGORIES
    ]
    # A record type a name never had is a detail, not a verdict; it must not headline a
    # report whose main question resolved. It still appears in 问题出在哪.
    minor = _by_severity([item for item in causes if item.get("severity") == "low"])
    deciding = [item for item in causes if item.get("severity") != "low"]
    confirmed = _by_severity([item for item in deciding if item.get("status") == "confirmed"])
    probable = _by_severity(
        [item for item in deciding if item.get("status") == "high_probability"]
    )
    resolved = [
        item for item in findings
        if item.get("category") == "resolution_succeeded"
        and item.get("status") == "confirmed"
    ]
    aside = (
        "另有 {0} 项次要发现，见“问题出在哪”。".format(len(minor)) if minor else ""
    )
    if confirmed:
        return "❌ 发现明确问题：{0}".format(_safe_text(confirmed[0].get("summary", "")))
    if probable:
        return "⚠️ 很可能有问题：{0}".format(_safe_text(probable[0].get("summary", "")))
    if resolved:
        # Saying "查到了地址" about a name that answered NOERROR with no address at all
        # contradicts the very table underneath it.
        opening = (
            "这台机器能正常查到 {0} 的地址".format(target_text) if has_address
            else "{0} 的查询都能正常应答（这个名字本身没有登记地址记录）".format(target_text)
        )
        text = (
            "✅ 一切正常。{0}，"
            "本次做过的各项检查没有发现被篡改或被拦截的迹象。".format(opening)
        )
        pending = [
            item for item in findings
            if item.get("category") in _INCONCLUSIVE_CATEGORIES
        ]
        if pending_rows or pending:
            # Do not let a clean headline swallow a check that never reached a verdict.
            text += "有 {0} 项检查没能得出结论，见下表的“❓ 待验证”。".format(
                pending_rows or len(pending)
            )
        return text + aside
    if any(item.get("category") == "resolution_succeeded" for item in findings):
        return (
            "✅ 看起来正常。{0} 能解析出地址，但样本较少，"
            "这一结论属于高概率而非已确认。".format(target_text) + aside
        )
    if minor:
        return "⚠️ 只发现一处次要问题：{0}".format(_safe_text(minor[0].get("summary", "")))
    return "❓ 无法判定。现有证据既不能确认正常，也不能指出具体问题，请看下面的两节说明。"


_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".home", ".corp", ".intranet")


def _private_addresses(evidence: dict, observations: List[dict]) -> List[str]:
    candidates: List[str] = []
    environment = evidence.get("environment")
    if isinstance(environment, dict):
        configuration = environment.get("resolver_configuration")
        if isinstance(configuration, dict):
            for value in configuration.get("resolver_addresses") or ():
                candidates.append(str(value))
    for item in observations:
        for value in item.get("resolver_addresses") or ():
            candidates.append(str(value))
        if item["resolver"] and item["resolver"] != "system":
            candidates.append(item["resolver"])
    private: List[str] = []
    for value in candidates:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if (address.is_private or address.is_link_local) and str(address) not in private:
            private.append(str(address))
    return private


def _internal_names(evidence: dict, observations: List[dict]) -> List[str]:
    names: List[str] = []
    target = evidence.get("target")
    if isinstance(target, dict):
        target = target.get("hostname") or target.get("ip")
    for value in [target] + [item["_qname"] for item in observations]:
        if not isinstance(value, str) or not value:
            continue
        name = value.rstrip(".")
        lowered = name.lower()
        looks_internal = (
            "." not in name
            or lowered.endswith(_INTERNAL_SUFFIXES)
        )
        if looks_internal and name not in names:
            names.append(name)
    return names


_REMOTE_REFUSAL_TEXT = {
    "not_acknowledged": "请求过异地观测，但没有加上确认参数，所以没有向第三方服务发出任何域名。",
    "internal_name": "请求过异地观测，但目标是内网名称，已直接拒绝：内网名称一旦发给第三方就收不回来。",
    "unsuitable_target": "请求过异地观测，但这个目标不是可以对外查询的普通域名，已跳过。",
    "measurement_failed": "请求过异地观测，但远端测量没有成功返回，所以这一层没有结果；本机各层的结论不受影响。",
}


def _remote_gap_line(evidence: dict) -> Optional[str]:
    """Say what happened to a requested remote observation instead of offering the flag."""
    entries = evidence.get("safety")
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("id") != "remote_query_disclosure":
            continue
        if entry.get("sent") or not entry.get("regions"):
            return None
        return _REMOTE_REFUSAL_TEXT.get(
            entry.get("reason_code"),
            "请求过异地观测，但这次没有执行，所以不知道别的国家或地区问到的是哪个地址。",
        )
    return None


def _gap_section(
    evidence: dict,
    observations: List[dict],
    findings: List[dict],
    matrix: dict,
    vantages: List[str],
) -> List[str]:
    layers = {_observation_layer(item) for item in observations}
    lines = ["## 没查到的部分", ""]
    lines.append(
        "- 结果只代表这台机器、这个时间点。换网络（公司 VPN、手机热点、别的机房）可能不一样。"
    )
    if "authoritative" not in layers:
        lines.append("- 没有直接问权威服务器，单靠解析器的答案不能确认问题的根源在哪一层。")
    if not isinstance(evidence.get("dnssec"), dict):
        lines.append("- 没有采集防篡改签名（DNSSEC）的证据，无法判断这个域名是否签名、签名是否有效。")
    if "trace" not in layers:
        lines.append("- 没有从根服务器逐级追查，看不出是哪一跳开始出问题。")
    refused = _remote_gap_line(evidence)
    if refused:
        lines.append("- {0}".format(refused))
    elif len(vantages) < 2:
        lines.append(
            "- 没有异地观测，不知道别的国家或地区问到的是哪个地址；需要的话加 `--regions US,DE`。"
        )
    else:
        regional = [item for item in observations if item.get("vantage") and item["_answers"]]
        if len({_answer_digest([item]) for item in regional}) > 1:
            lines.append(
                "- 各地区之间答案不同，往往只是按地区就近分配（CDN），不等于被篡改；"
                "Anycast 与由 IP 推断出的地理位置都只是近似信息。"
            )
        else:
            # The regions agreed, so the caveat is about how little agreement proves,
            # not about a difference this run never saw.
            lines.append(
                "- 各地区答案一致只代表这几个观测点、这个时间点；换地区或换时间仍可能不同，"
                "Anycast 与由 IP 推断出的地理位置也都只是近似信息。"
            )
        remote_types = {item["_qtype"] for item in regional if item["_qtype"]}
        local_only = sorted({
            item["_qtype"] for item in observations
            if item["_qtype"] and _observation_layer(item) not in {"regional", "dnssec"}
            # DS and DNSKEY belong to the signature check, and comparing them by region
            # answers nothing, so listing them here would only be noise.
            and item["_qtype"] not in {"DS", "DNSKEY"}
        } - remote_types)
        if remote_types and local_only:
            # The overview row says the regions agree; it must not be read as agreement
            # about record types the remote comparison never asked for.
            lines.append(
                "- 异地观测只对比了{0}，{1}没有在别的地区比对过。".format(
                    "、".join(
                        _RECORD_TYPE_LABELS.get(item, item) for item in sorted(remote_types)
                    ),
                    "、".join(_RECORD_TYPE_LABELS.get(item, item) for item in local_only),
                )
            )
    lines.append("- 缓存、TTL 未到期、以及路上未被记录的中间设备都可能影响这次结果。")
    lines.append("")
    return lines


def _remote_send_line(evidence: dict) -> Optional[str]:
    """State plainly whether a name left this machine, and exactly what left."""
    for entry in evidence.get("safety") or ():
        if not isinstance(entry, dict) or entry.get("id") != "remote_query_disclosure":
            continue
        if not entry.get("sent"):
            return None
        regions = [_vantage_text(item) for item in entry.get("regions") or []]
        fields = "域名和记录类型"
        if entry.get("record_type"):
            fields = "域名与记录类型（{0}）".format(_safe_text(entry["record_type"]))
        return (
            "- 这次做了异地观测：{0}被发给 {1}，用来取得 {2} 的结果。"
            "采集到的命令输出、内网解析器地址、搜索域都没有发送。".format(
                fields,
                _safe_text(entry.get("endpoint") or "远端观测服务"),
                "、".join(regions) or "指定地区",
            )
        )
    return None


def _privacy_section(evidence: dict, observations: List[dict]) -> List[str]:
    lines = ["## 分享前请注意", ""]
    private = _private_addresses(evidence, observations)
    internal = _internal_names(evidence, observations)
    if private:
        lines.append(
            "- 这次产物里出现了内网解析器地址（{0}），`dns-debug-report.json` 会完整保留它们，"
            "发给外部等于暴露内网结构，转发前请自行删除。".format("、".join(private))
        )
    if internal:
        lines.append(
            "- 这次产物里出现了内网域名（{0}），这类名称只在你们内部有意义，外发会泄漏内部命名。".format(
                "、".join(_safe_text(name) for name in internal)
            )
        )
    for item in evidence.get("safety") or ():
        if isinstance(item, dict) and item.get("note"):
            lines.append("- {0}".format(_safe_text(item["note"])))
    if not private and not internal:
        lines.append("- 未发现内网地址或内网域名；仍建议在外发前自己再看一遍全文。")
    sent = _remote_send_line(evidence)
    if sent:
        # The contract is that this section says whether anything left the machine, so a
        # run that did send something must not be summarized as "nothing was sent".
        lines.append(sent)
        lines.append("- 除此之外没有任何外发：报告与原始记录都只留在本机，不会自动上传。")
    else:
        lines.append("- 全程没有向任何人发送内容，报告与原始记录都只留在本机。")
    lines.append("")
    return lines


def _next_section(findings: List[dict]) -> List[str]:
    lines = ["## 接下来可以做什么", ""]
    causes = [
        item for item in findings
        if item.get("category") not in _NON_CAUSE_CATEGORIES
        and item.get("status") in {"confirmed", "high_probability"}
    ]
    steps: List[str] = []
    for item in causes:
        for step in item.get("next_checks") or ():
            text = _safe_text(step)
            if text not in steps:
                steps.append(text)
    if not causes:
        lines.append(
            "DNS 这一层没有发现问题。若业务仍异常，请继续往后查：HTTP、TLS 证书、代理设置或应用本身。"
        )
    else:
        for step in steps or ["按上一节的发现逐条核实，必要时联系域名或网络的负责人。"]:
            lines.append("- {0}".format(step))
    extra: List[str] = []
    for item in findings:
        if item.get("status") != "unverified":
            continue
        for step in item.get("next_checks") or ():
            text = _safe_text(step)
            if text not in steps and text not in extra:
                extra.append(text)
    if extra:
        lines.extend(["", "想更有把握，还可以补：", ""])
        lines.extend("- {0}".format(step) for step in extra)
    lines.extend(["", "完整原始数据见同目录 `dns-debug-report.json`。"])
    return lines


def _elapsed_text(observations: List[dict]) -> str:
    starts = [item["_observed_at"] for item in observations if item["_observed_at"]]
    durations = _durations_ms(observations)
    if not starts:
        return ""
    span = (max(starts) - min(starts)).total_seconds()
    if durations:
        span += durations[-1] / 1000.0
    return "{0} 秒".format(max(1, round(span)))


def render_report(evidence: dict, findings: List[dict], language: str = "zh-CN") -> str:
    """Render a plain-language Chinese Markdown report backed only by observations."""
    if language not in {"zh-CN", "zh"}:
        raise ValueError("only zh-CN report rendering is supported")
    if not isinstance(evidence, dict) or not isinstance(findings, list):
        raise TypeError("evidence must be a mapping and findings must be a list")
    observations = _observations_from_evidence(evidence)
    matrix = compare_regional_answers(observations)
    target = evidence.get("target", "未提供")
    if isinstance(target, dict):
        target = target.get("hostname") or target.get("ip") or "未提供"
    target_text = _safe_text(target)
    probe_layers = {item["id"]: _observation_layer(item) for item in observations}
    vantages = _vantage_labels(observations)

    header = ["**域名**：{0}".format(target_text)]
    collected_at = _normalized_observed_at(evidence.get("collected_at"))
    if collected_at is not None:
        # Shown in the reader's own clock; the JSON keeps the UTC original.
        header.append("**时间**：{0}（本机时区）".format(
            collected_at.astimezone().strftime("%Y-%m-%d %H:%M")
        ))
    elapsed = _elapsed_text(observations)
    if elapsed:
        header.append("**用时**：{0}".format(elapsed))
    header.append("**查询次数**：{0}".format(len(observations)))

    rows = []
    for layer in _LAYER_ORDER:
        row_observations = [
            item for item in observations
            if (_observation_layer(item) == layer
                or (layer == "regional" and item.get("vantage")))
        ]
        row_findings = [
            item for item in findings
            if layer in _finding_layers(item, probe_layers)
        ]
        if layer == "regional" and len(vantages) < 2 and not row_findings:
            continue
        if not row_observations and not row_findings:
            continue
        rows.append(_layer_row(layer, row_findings, row_observations, evidence) + (layer,))

    lines = [
        "# DNS 诊断报告",
        "",
        "　".join(header),
        "",
        "## 结论",
        "",
        # The headline counts the rows a reader can actually see, not every internal
        # finding: promising two "❓" lines and printing one reads as a bug.
        _conclusion(
            findings,
            target_text,
            sum(1 for row in rows if row[0] == "❓"),
            any(_addresses_by_family(observations)),
        ),
        "",
        "## 检查项一览",
        "",
        "| 检查项 | 结果 | 说明 |",
        "| --- | --- | --- |",
    ]
    for icon, verdict, note, layer in rows:
        lines.append("| {0} | {1} {2} | {3} |".format(
            _LAYER_TITLES[layer], icon, verdict, note or "—",
        ))
    lines.extend([
        "",
        "> 结果列含义：✅ 已确认　❌ 已确认有问题　⚠️ 高概率　❓ 待验证　⚪ 不适用",
        "",
    ])
    lines.extend(_topology_section(evidence, observations, findings, target_text))
    lines.extend(_observed_section(evidence, observations, findings, target_text))
    lines.extend(_cause_section(findings))
    lines.extend(_gap_section(evidence, observations, findings, matrix, vantages))
    lines.extend(_privacy_section(evidence, observations))
    lines.extend(_next_section(findings))
    return "\n".join(lines) + "\n"


def _analysis_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze an existing DNS evidence JSON file without network access."
    )
    parser.add_argument("--input", required=True, type=Path, help="existing evidence JSON path")
    parser.add_argument("--output", required=True, type=Path, help="local Markdown report path")
    parser.add_argument(
        "--finalize-bundle",
        action="store_true",
        help="update canonical bundle JSON/artifacts and replace its Markdown report",
    )
    return parser


def _validate_analysis_paths(input_path: Path, output_path: Path) -> None:
    if input_path.suffix.lower() != ".json" or not input_path.is_file():
        raise ValueError("input must be an existing JSON file")
    if input_path.is_symlink():
        raise ValueError("input JSON path must not be a symlink")
    if input_path.stat().st_size > _MAX_INPUT_BYTES:
        raise ValueError("input JSON exceeds the 4 MiB offline analysis limit")
    if input_path.resolve() == output_path.resolve():
        raise ValueError("input and output must be different paths")
    if output_path.is_symlink():
        raise ValueError("output path must not be a symlink")
    if output_path.exists() and not output_path.is_file():
        raise ValueError("output path must be a file")
    if not output_path.parent.is_dir() or output_path.parent.is_symlink():
        raise ValueError("output parent must be an existing non-symlink directory")


def _validate_finalize_paths(input_path: Path, output_path: Path) -> None:
    expected_output = input_path.parent / "dns-debug-report.md"
    if input_path.name != "dns-debug-report.json" or output_path.resolve() != expected_output.resolve():
        raise ValueError(
            "--finalize-bundle requires canonical dns-debug-report.json and dns-debug-report.md paths"
        )


def _load_bundle_writer():
    module_path = Path(__file__).with_name("dns_probe.py")
    spec = importlib.util.spec_from_file_location("tom_dns_debug_probe_for_finalize", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load local bundle writer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.write_bundle


def main(argv: Optional[List[str]] = None) -> int:
    parser = _analysis_argument_parser()
    args = parser.parse_args(argv)
    try:
        _validate_analysis_paths(args.input, args.output)
        if args.finalize_bundle:
            _validate_finalize_paths(args.input, args.output)
        evidence = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(evidence, dict):
            raise ValueError("input JSON must contain an evidence object")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    findings = classify_evidence(evidence)
    report = render_report(evidence, findings, language="zh-CN")
    try:
        if args.finalize_bundle:
            evidence["findings"] = findings
            write_bundle = _load_bundle_writer()
            write_bundle(evidence, args.input.parent)
        args.output.write_text(report, encoding="utf-8")
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error("could not write local report: {0}".format(exc))
    print(str(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
