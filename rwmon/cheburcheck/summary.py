"""Condense raw Cheburcheck data and relate it to the monitor's own findings.

Two kinds of data are kept strictly apart:

* static  – presence in registries and lists ("listed" is not "blocked");
* dynamic – what volunteer probes at Russian ISPs measured just now.

Cheburcheck probes test the path to port 443 beyond the ISP's DPI hop, the
SNI against Cheburcheck's own hosts, and DNS answers. They never test the VPN
port or protocol, so their data supports a hypothesis and never replaces the
monitor's own result.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

# Verdicts a probe may report, in the service's own order of priority.
#
#   tspu_block    packets to the IP stop right behind the operator's DPI hop
#   sni_block     a ClientHello with this SNI gets no answer even from control hosts that normally work
#   dns_spoofing  plain DNS answers differ from DoH/DoT answers
#   whitelist     this SNI is exempt from the "16-20 KB" restriction of foreign CDN/hosting ranges
#   cdn_block     the operator applies that restriction and this SNI is not exempt. This is the ordinary
#                 state of any ordinary name: it concerns a server only if its IP is in such a range
#   ok            nothing of the above
#   uncertain     the probe could not tell
PRIORITY = ("tspu_block", "sni_block", "dns_spoofing", "whitelist", "cdn_block", "ok", "uncertain")
BLOCKING = ("tspu_block", "sni_block", "dns_spoofing")       # evidence that the target itself is blocked
CLEAR = ("ok", "whitelist", "cdn_block")                      # the probe saw no block of the target
LISTED_PLACES = BLOCKING + ("cdn_block",)                     # verdicts shown with regions and operators
LABELS = {
    "tspu_block": "Блокировка на ТСПУ",
    "sni_block": "Блокировка по SNI",
    "dns_spoofing": "Подмена DNS",
    "whitelist": "SNI в исключениях для CDN («белый список»)",
    "cdn_block": "Действует ограничение CDN 16–20 КБ, SNI не в исключениях",
    "ok": "Блокировки не видно",
    "uncertain": "Неясно",
}
CDN_NOTE = ("Ограничение CDN — свойство оператора, а не блокировка адреса: оно касается сервера, "
            "только если его IP входит в диапазоны CDN/хостингов.")

# Reliability of the data shown to the owner.
FRESH = "fresh"
CACHED = "cached"
PARTIAL = "partial"
PENDING = "pending"
UNAVAILABLE = "unavailable"
NOT_APPLICABLE = "na"
DISABLED = "disabled"
RELIABILITY = {
    FRESH: "✅ данные получены",
    CACHED: "🕒 данные из кеша сервиса (замеры давностью до 3 ч)",
    PARTIAL: "◐ данные частичные",
    PENDING: "⏳ данные запрашиваются, сообщение будет дополнено",
    UNAVAILABLE: "⚠️ сервис временно недоступен, запрос будет повторён",
    NOT_APPLICABLE: "⛔ неприменимо для этой цели",
    DISABLED: "выключен в настройках",
}


def _text(value: Any, limit: int = 80) -> str:
    return str(value)[:limit] if value not in (None, "", "-") else ""


def summarize_static(data: dict[str, Any]) -> dict[str, Any]:
    """Trim the /check response to the facts worth keeping."""
    geo = data.get("geo") if isinstance(data.get("geo"), dict) else {}
    cdn_raw = data.get("cdn_providers") if isinstance(data.get("cdn_providers"), dict) else {}
    cdn = []
    for name, records in list(cdn_raw.items())[:4]:
        first = records[0] if isinstance(records, list) and records and isinstance(records[0], dict) else {}
        cdn.append({"provider": _text(name, 40), "cidr": _text(first.get("cidr"), 50), "region": _text(first.get("region"), 30)})
    asn_info = data.get("asn_info") if isinstance(data.get("asn_info"), dict) else {}
    complaints = data.get("complaints") if isinstance(data.get("complaints"), list) else []
    recent = sum(int(day.get("count") or 0) for day in complaints[-7:] if isinstance(day, dict))
    subnets = data.get("blocked_subnets") if isinstance(data.get("blocked_subnets"), list) else []
    ips = data.get("ips") if isinstance(data.get("ips"), list) else []
    return {
        "target_type": _text(data.get("target_type"), 30),
        "listed": bool(data.get("blocked")),
        "rkn_domain": _text(data.get("rkn_domain"), 120),
        "blocked_subnets": [_text(item, 50) for item in subnets[:5]],
        "ips": [_text(item, 50) for item in ips[:8]],
        "cdn": cdn,
        "asn": _text(geo.get("asn"), 20),
        "org": _text(geo.get("organisation")),
        "country": _text(geo.get("country_code"), 8),
        "location": _text(geo.get("location"), 60),
        "whitelisted": bool(data.get("whitelist")),
        "asn_prefixes": len(asn_info.get("prefixes") or []),
        "asn_blocked_prefixes": len(asn_info.get("blocked_prefixes") or []),
        "complaints_7d": recent,
    }


def primary_verdict(verdicts: list[Any]) -> str:
    found = [item for item in verdicts if isinstance(item, str)]
    for verdict in PRIORITY:
        if verdict in found:
            return verdict
    return "uncertain"


def trim_probe(item: dict[str, Any]) -> dict[str, Any]:
    verdicts = [str(v)[:24] for v in (item.get("verdicts") or []) if isinstance(v, str)]
    return {
        "region": _text(item.get("region"), 60) or "регион не указан",
        "provider": _text(item.get("provider"), 40) or "оператор не указан",
        "asn": _text(item.get("asn"), 16),
        "verdicts": verdicts,
        "verdict": primary_verdict(verdicts),
        "cached": bool(item.get("cached")),
        "dpi_hop": item.get("dpi_hop") if isinstance(item.get("dpi_hop"), int) else None,
        "target_hop": item.get("target_hop") if isinstance(item.get("target_hop"), int) else None,
    }


def _places(probes: list[dict[str, Any]], limit: int = 4) -> tuple[list[str], int]:
    """'Region (ISP, ISP)' strings, biggest regions first, plus the number left out."""
    regions: dict[str, list[str]] = {}
    for probe in probes:
        providers = regions.setdefault(probe["region"], [])
        if probe["provider"] not in providers:
            providers.append(probe["provider"])
    ordered = sorted(regions.items(), key=lambda pair: (-len(pair[1]), pair[0]))
    shown = [f"{region} ({', '.join(providers[:3])}{'…' if len(providers) > 3 else ''})" for region, providers in ordered[:limit]]
    return shown, max(0, len(ordered) - limit)


def summarize_probes(probes: list[dict[str, Any]], online: int, done: bool) -> dict[str, Any]:
    """Aggregate trimmed per-probe results."""
    counts = Counter(probe["verdict"] for probe in probes)
    flags = Counter(flag for probe in probes for flag in probe["verdicts"])
    places: dict[str, Any] = {}
    for verdict in LISTED_PLACES:
        selected = [probe for probe in probes if probe["verdict"] == verdict]
        if selected:
            shown, more = _places(selected, 3 if verdict == "cdn_block" else 4)
            places[verdict] = {"shown": shown, "more": more}
    operators = Counter(probe["provider"] for probe in probes if probe["verdict"] in BLOCKING)
    return {
        "responses": len(probes),
        "online": int(online or 0),
        "done": bool(done),
        "counts": {verdict: counts[verdict] for verdict in PRIORITY if counts[verdict]},
        "flags": dict(flags),
        "cached": sum(1 for probe in probes if probe["cached"]),
        "places": places,
        "operators_blocked": dict(operators.most_common(6)),
        "blocked": sum(counts[verdict] for verdict in BLOCKING),
        "clear": sum(counts[verdict] for verdict in CLEAR),
        "uncertain": counts["uncertain"],
    }


def reliability(static_status: str, probe_status: str, summary: dict[str, Any]) -> str:
    if static_status == "rejected":
        return NOT_APPLICABLE
    if static_status == "disabled":
        return DISABLED
    if static_status != "ok":
        return UNAVAILABLE
    if probe_status == "rejected":
        return NOT_APPLICABLE
    if probe_status != "ok":
        return PARTIAL
    probes = summary.get("probes") or {}
    responses = probes.get("responses") or 0
    if responses and probes.get("cached", 0) * 2 > responses:
        return CACHED
    return FRESH


# ── likely cause ────────────────────────────────────────────────────────────

MIN_PROBES = 3     # fewer decisive answers than this are not evidence
MAJORITY = 0.5     # share of decisive probes reporting a block: "blocked"
NOTICEABLE = 0.25  # ...: "blocked at some ISPs"; below it is measurement noise


def _decisive(summary: dict[str, Any] | None) -> tuple[int, int, dict[str, int]]:
    """(saw a block, saw no block, counts) from the dynamic part, or zeros when there is none."""
    probes = (summary or {}).get("probes") or {}
    counts = probes.get("counts") or {}
    blocked = sum(int(counts.get(verdict) or 0) for verdict in BLOCKING)
    clear = sum(int(counts.get(verdict) or 0) for verdict in CLEAR)
    return blocked, clear, counts


def _cdn_restriction(by_kind: dict[str, dict[str, Any] | None]) -> str:
    """Name of the CDN/hosting range the server's IP belongs to, if probes also see the 16-20 KB restriction."""
    provider = ""
    for kind in ("ip", "domain", "sni"):
        cdn = ((by_kind.get(kind) or {}).get("static") or {}).get("cdn") or []
        if cdn:
            provider = str(cdn[0].get("provider") or "CDN")
            break
    if not provider:
        return ""
    restricted = max(int((((by_kind.get(kind) or {}).get("probes") or {}).get("counts") or {}).get("cdn_block", 0))
                     for kind in ("domain", "sni"))
    return provider if restricted >= MIN_PROBES else ""


def assess(code: str, stage: str, by_kind: dict[str, dict[str, Any] | None]) -> str:
    """A cautious hypothesis about the cause. ``by_kind`` maps ip/domain/sni → summary.

    The text continues the label "Вероятная причина:" — it is always presented
    as a likelihood, because the probes measure something adjacent to, not
    identical with, what the monitor checks.
    """
    ip_blocked, ip_ok, _ = _decisive(by_kind.get("ip"))
    dom_blocked, dom_ok, dom_counts = _decisive(by_kind.get("domain"))
    sni_blocked, sni_ok, sni_counts = _decisive(by_kind.get("sni"))
    have_dynamic = (ip_blocked + ip_ok + dom_blocked + dom_ok + sni_blocked + sni_ok) >= MIN_PROBES

    if code == "tcp_refused":
        return "сбой сервиса на сервере: порт отвечает отказом, блокировки так обычно не выглядят"
    if code in ("dns_nxdomain", "dns_nodata"):
        if dom_counts.get("dns_spoofing", 0) >= MIN_PROBES:
            return "подмена DNS у операторов (её фиксируют сканеры Cheburcheck)"
        return "проблема с DNS-записью домена: домен удалён, не продлён или запись убрана"
    if not have_dynamic:
        if code.startswith("e2e_"):
            return ("блокировка протокола либо сбой Xray на сервере; региональных замеров Cheburcheck нет, "
                    "вывод сделан только по собственным проверкам")
        return ""

    def share(blocked: int, ok: int) -> float:
        return blocked / (blocked + ok) if blocked + ok else 0.0

    ip_share, dom_share, sni_share = share(ip_blocked, ip_ok), share(dom_blocked, dom_ok), share(sni_blocked, sni_ok)
    ip_enough = ip_blocked + ip_ok >= MIN_PROBES

    if code in ("tcp_timeout", "net_unreachable", "tcp_reset", "udp_no_reply", "tcp_error"):
        if not ip_enough:
            return ""
        total = ip_blocked + ip_ok
        if ip_share >= MAJORITY:
            return f"блокировка IP на ТСПУ (её видят {ip_blocked} из {total} сканеров с определённым результатом)"
        if ip_share >= NOTICEABLE:
            return (f"блокировка IP у части операторов ({ip_blocked} из {total} сканеров); "
                    "у остальных пакеты проходят")
        noise = f" ({ip_blocked} из {total} сообщают о блокировке — это уровень погрешности замеров)" if ip_blocked else ""
        return ("отказ сервера или сети хостера либо блокировка, специфичная для порта: блокировки IP на ТСПУ "
                "сканеры не видят" + noise + " (они проверяют только путь до 443-го порта)")
    if code in ("tls_reset", "tls_timeout", "tls_eof", "tls_error"):
        sni_evidence = max(
            (sni_counts.get("sni_block", 0), sni_blocked + sni_ok),
            (dom_counts.get("sni_block", 0), dom_blocked + dom_ok),
        )
        if sni_evidence[0] >= MIN_PROBES and sni_evidence[0] >= sni_evidence[1] * NOTICEABLE:
            return f"блокировка по SNI (её фиксируют {sni_evidence[0]} из {sni_evidence[1]} сканеров)"
        if ip_enough and ip_share >= MAJORITY:
            return f"блокировка IP на ТСПУ ({ip_blocked} из {ip_blocked + ip_ok} сканеров)"
        if max(dom_share, sni_share, ip_share) < NOTICEABLE:
            return ("блокировка по сигнатуре протокола либо неисправность сервиса на сервере: "
                    "блокировок по IP и SNI сканеры не видят")
        return "блокировка у части операторов: картина по сканерам неоднородна"
    if code.startswith("e2e_"):
        if max(ip_share, dom_share, sni_share) >= MAJORITY:
            return "блокировка на ТСПУ: сканеры видят блокировку адреса или домена у операторов"
        if code == "e2e_stall":
            provider = _cdn_restriction(by_kind)
            if provider:
                return (f"ограничение CDN 16–20 КБ: IP сервера входит в диапазон {provider}, а его SNI "
                        "не входит в исключения (это видят сканеры Cheburcheck)")
            return ("ограничение объёма передачи на ТСПУ (обрыв после 16–20 КБ); "
                    "блокировки адреса сканеры не видят")
        return ("блокировка протокола либо сбой Xray на сервере: блокировки адреса и домена сканеры не видят "
                "(такие блокировки Cheburcheck не измеряет)")
    return ""
