"""Configuration, secrets, masking, time formatting, Cheburcheck summaries."""

import json
import logging

import pytest
from pydantic import ValidationError

from rwmon.cheburcheck import summary as sm
from rwmon.config import (
    Config,
    load_config,
    parse_intervals,
    scrub_proxy_env,
    validate_proxy_url,
)
from rwmon.logging_setup import MaskingFormatter
from rwmon.security import MASKER, SecretBox, mask_proxy, mask_url
from rwmon.timeutil import fmt_duration, fmt_interval, fmt_time, parse_duration

from ..conftest import TOKEN, make_config
from ..fakes.cheburcheck import FIXTURES, load_probe_events


def test_config_requires_token_owner_and_key(tmp_path):
    with pytest.raises(ValidationError):
        Config(_env_file=None)
    with pytest.raises(ValidationError):
        make_config(tmp_path, telegram_bot_token="not-a-token")
    with pytest.raises(ValidationError):
        make_config(tmp_path, telegram_owner_id="@username")        # must be a numeric id
    with pytest.raises(ValidationError):
        make_config(tmp_path, fail_threshold=1)                      # a single failure may never mean DOWN
    with pytest.raises(ValidationError):
        make_config(tmp_path, telegram_proxy_url="ftp://host:21")
    config = make_config(tmp_path)
    assert config.telegram_owner_id == 777000111 and config.db_path == tmp_path / "rwmon.sqlite3"
    assert TOKEN not in repr(config) and config.secret_key.get_secret_value() not in repr(config)


def test_config_from_env_file(tmp_path, monkeypatch):
    for name in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_OWNER_ID", "SECRET_KEY"):
        monkeypatch.delenv(name, raising=False)
    env = tmp_path / "rwmon.env"
    env.write_text("\n".join([
        f"TELEGRAM_BOT_TOKEN={TOKEN}", "TELEGRAM_OWNER_ID=42", f"SECRET_KEY={SecretBox.generate_key()}",
        "TELEGRAM_PROXY_URL=socks5h://user:pw@10.0.0.5:1080", "CHECK_INTERVAL=300", "RECHECK_INTERVALS=20,40,60",
        f"DATA_DIR={tmp_path}", "CHEBURCHECK_ENABLED=false", "# comment",
    ]))
    config = load_config(env)
    assert config.telegram_owner_id == 42 and config.check_interval == 300
    assert config.telegram_proxy_url == "socks5://user:pw@10.0.0.5:1080"      # remote DNS is implied
    assert config.cheburcheck_enabled is False and parse_intervals(config.recheck_intervals) == [20, 40, 60]


def test_proxy_validation_and_masking():
    assert validate_proxy_url("") == ""
    assert validate_proxy_url("http://proxy.local:3128") == "http://proxy.local:3128"
    for bad in ("socks5://host", "host:1080", "socks5://:1080"):
        with pytest.raises(ValueError):
            validate_proxy_url(bad)
    assert mask_proxy("socks5://user:secret@1.2.3.4:1080") == "socks5://***@1.2.3.4:1080"
    assert mask_proxy("") == "без прокси"
    assert mask_url("https://panel.example.com/sub/AbCdEfGh12345678") == "panel.example.com/…5678"


def test_proxy_environment_is_scrubbed(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://corp:3128")
    monkeypatch.setenv("all_proxy", "socks5://x:1")
    removed = scrub_proxy_env()
    import os
    assert set(removed) >= {"HTTPS_PROXY", "all_proxy"} and "HTTPS_PROXY" not in os.environ


def test_secret_box_roundtrip_and_wrong_key():
    box = SecretBox(SecretBox.generate_key())
    blob = box.encrypt("https://panel/sub/secret")
    assert b"secret" not in blob and box.decrypt(blob) == "https://panel/sub/secret"
    with pytest.raises(ValueError):
        SecretBox(SecretBox.generate_key()).decrypt(blob)


def test_log_masking_covers_tokens_urls_links_and_registered_secrets():
    MASKER.register("https://panel.example.com/sub/SuperSecretToken", "panel.example.com/…oken")
    formatter = MaskingFormatter("%(message)s")

    def render(message, *args):
        return formatter.format(logging.LogRecord("t", logging.INFO, "", 0, message, args, None))

    assert TOKEN not in render("POST https://api.telegram.org/bot%s/sendMessage", TOKEN)
    assert "SuperSecretToken" not in render("fetch %s failed", "https://panel.example.com/sub/SuperSecretToken")
    assert "pa55" not in render("proxy socks5://bob:pa55@10.1.1.1:1080 is down")
    line = render("bad link vless://5d2f7c1e-3b6a-4c8d-9e0f-000000000001@host.example:443?pbk=KEY#name")
    assert "5d2f7c1e-3b6a-4c8d-9e0f-000000000001" not in line
    try:
        raise RuntimeError(f"boom {TOKEN}")
    except RuntimeError:
        import sys
        record = logging.LogRecord("t", logging.ERROR, "", 0, "failed", (), sys.exc_info())
    assert TOKEN not in formatter.format(record)                     # tracebacks are masked too


def test_time_helpers():
    assert parse_duration("90") == 90 and parse_duration("5m") == 300 and parse_duration("2 ч") == 7200
    assert parse_duration("1.5h") == 5400 and parse_duration("1d") == 86400
    assert parse_duration("abc") is None and parse_duration("-5") is None and parse_duration("") is None
    assert fmt_interval(45) == "45 с" and fmt_interval(180) == "3 мин" and fmt_interval(7200) == "2 ч"
    assert fmt_duration(59) == "59 секунд" and fmt_duration(17 * 60) == "17 минут" and fmt_duration(3 * 3600 + 300) == "3 ч 05 мин" and fmt_duration(3600) == "1 ч" and fmt_duration(2 * 86400) == "2 д"
    assert fmt_time(1794300000).endswith("МСК") and fmt_time(None) == "—"
    assert fmt_time(1700000000) == "01:13:20 МСК"                    # 2023-11-14 22:13:20 UTC = 01:13:20 in Moscow


def _summary(name: str, verdict: str | None = None, share: float = 1.0) -> dict:
    probes = [sm.trim_probe(data) for event, data in load_probe_events(name) if event == "result"]
    if verdict:
        cut = int(len(probes) * share)
        for index, probe in enumerate(probes):
            probe["verdicts"] = [verdict] if index < cut else ["ok"]
            probe["verdict"] = sm.primary_verdict(probe["verdicts"])
    return {"static": {}, "probes": sm.summarize_probes(probes, 41, True)}


def test_real_probe_stream_is_summarised():
    summary = _summary("rutracker.org")["probes"]
    assert summary["responses"] >= 30 and summary["counts"]["sni_block"] >= 20
    assert summary["flags"]["dns_spoofing"] >= 20            # a probe may report several verdicts
    assert summary["places"]["sni_block"]["shown"] and "(" in summary["places"]["sni_block"]["shown"][0]
    static = sm.summarize_static(json.loads((FIXTURES / "check_rutracker.org.json").read_text()))
    assert static["listed"] and static["rkn_domain"] == "rutracker.org" and static["asn"] == "AS13335"
    assert static["cdn"][0]["provider"] == "cloudflare"


def test_summaries_tolerate_missing_and_odd_fields():
    assert sm.summarize_static({})["listed"] is False
    assert sm.summarize_static({"geo": None, "cdn_providers": [], "complaints": "x", "ips": None})["cdn"] == []
    probe = sm.trim_probe({"verdicts": None, "region": None})
    assert probe["verdict"] == "uncertain" and probe["region"] == "регион не указан"
    assert sm.summarize_probes([], 0, False)["responses"] == 0


def test_reliability_levels():
    assert sm.reliability("ok", "ok", _summary("1.1.1.1")) == sm.FRESH
    assert sm.reliability("ok", "partial", {}) == sm.PARTIAL
    assert sm.reliability("ok", "unavailable", {}) == sm.PARTIAL
    assert sm.reliability("unavailable", "skipped", {}) == sm.UNAVAILABLE
    assert sm.reliability("rejected", "skipped", {}) == sm.NOT_APPLICABLE
    cached = {"probes": {"responses": 10, "cached": 8}}
    assert sm.reliability("ok", "ok", cached) == sm.CACHED


def test_likely_cause_is_cautious():
    blocked = _summary("1.1.1.1", "tspu_block", 0.9)
    clean = _summary("1.1.1.1", "tspu_block", 0.0)
    noise = _summary("1.1.1.1", "tspu_block", 0.08)
    some = _summary("1.1.1.1", "tspu_block", 0.35)
    assert sm.assess("tcp_timeout", "tcp", {"ip": blocked}).startswith("блокировка IP на ТСПУ")
    assert "у части операторов" in sm.assess("tcp_timeout", "tcp", {"ip": some})
    text = sm.assess("tcp_timeout", "tcp", {"ip": noise})
    assert "не видят" in text and "погрешности" in text and "отказ сервера" in text
    assert "отказ сервера" in sm.assess("tcp_timeout", "tcp", {"ip": clean})
    assert "сбой сервиса" in sm.assess("tcp_refused", "tcp", {"ip": blocked})       # a refusal is not a block
    assert "блокировка по SNI" in sm.assess("tls_reset", "tls", {"domain": _summary("rutracker.org")})
    assert "протокола" in sm.assess("e2e_failed", "e2e", {"ip": clean})
    assert "16–20 КБ" in sm.assess("e2e_stall", "e2e", {"ip": clean})
    assert sm.assess("tcp_timeout", "tcp", {}) == ""                                # no data → no hypothesis
    assert sm.assess("tcp_timeout", "tcp", {"ip": {"static": {"listed": True}}}) == ""   # lists alone prove nothing
    # every hypothesis is a noun phrase that continues the label "Вероятная причина:"
    assert all(sm.assess(code, "", {"ip": blocked})[0].islower() for code in ("tcp_timeout", "tls_timeout", "e2e_failed"))


def _domain_summary(verdicts: dict[str, int], cdn: bool = False) -> dict:
    probes = []
    for verdict, count in verdicts.items():
        probes += [{"region": f"Регион {index}", "provider": "ISP", "asn": "", "verdicts": [verdict], "verdict": verdict,
                    "cached": False, "dpi_hop": None, "target_hop": None} for index in range(count)]
    static = {"cdn": [{"provider": "cloudflare", "cidr": "104.21.0.0/17", "region": ""}]} if cdn else {}
    return {"static": static, "probes": sm.summarize_probes(probes, 40, True)}


def test_cdn_restriction_is_not_mistaken_for_a_block():
    """`cdn_block` / `whitelist` describe the operator's CDN policy, not a block of the target."""
    domain = _domain_summary({"cdn_block": 6, "ok": 3, "whitelist": 2, "uncertain": 1})
    probes = domain["probes"]
    assert probes["blocked"] == 0 and probes["clear"] == 11
    assert "cdn_block" in probes["places"] and "whitelist" not in probes["places"]
    text = sm.assess("tls_timeout", "tls", {"domain": domain, "ip": _summary("1.1.1.1", "tspu_block", 0.0)})
    assert text.startswith("блокировка по сигнатуре протокола либо неисправность сервиса")
    assert sm.assess("tcp_timeout", "tcp", {"ip": _domain_summary({"cdn_block": 9, "ok": 1})}).startswith("отказ сервера")
    assert "не блокировка адреса" in sm.CDN_NOTE and "исключениях" in sm.LABELS["whitelist"]
    # the restriction matters when the server sits in a CDN/hosting range and data stalls after ~16 KB
    stalled = sm.assess("e2e_stall", "e2e", {"ip": _domain_summary({"ok": 9}, cdn=True),
                                             "domain": _domain_summary({"cdn_block": 7, "ok": 2})})
    assert stalled.startswith("ограничение CDN 16–20 КБ: IP сервера входит в диапазон cloudflare")
    no_cdn = sm.assess("e2e_stall", "e2e", {"ip": _domain_summary({"ok": 9}), "domain": _domain_summary({"cdn_block": 7})})
    assert no_cdn.startswith("ограничение объёма передачи на ТСПУ")
    # a real SNI block is still recognised
    blocked = sm.assess("tls_reset", "tls", {"domain": _domain_summary({"sni_block": 8, "cdn_block": 2})})
    assert blocked.startswith("блокировка по SNI (её фиксируют 8 из 10")
