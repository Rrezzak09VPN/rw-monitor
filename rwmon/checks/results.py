"""Result objects and failure vocabulary shared by all check layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Failure code -> text shown to the owner as the reason.
REASONS: dict[str, str] = {
    "ok": "доступен",
    "dns_nxdomain": "домен не существует (NXDOMAIN, подтверждено несколькими DNS)",
    "dns_nodata": "у домена нет A/AAAA-записей",
    "dns_unavailable": "DNS-резолверы не отвечают — проверить сервер невозможно",
    "tcp_timeout": "нет ответа на TCP-соединение (таймаут) — характерно для блокировки IP или недоступности хоста",
    "tcp_refused": "TCP-соединение отклонено — порт закрыт или сервис не запущен",
    "tcp_reset": "TCP-соединение сброшено при установке",
    "net_unreachable": "сеть или хост недостижимы (нет маршрута)",
    "tcp_error": "ошибка TCP-соединения",
    "udp_no_reply": "сервер не отвечает по UDP (QUIC)",
    "udp_unreachable": "UDP-порт закрыт (ICMP port unreachable)",
    "udp_unverifiable": "UDP-протокол с обфускацией: без сквозной проверки достоверно проверить нельзя",
    "tls_timeout": "нет ответа на TLS ClientHello — характерно для блокировки по SNI/сигнатуре или «пустого» порта",
    "tls_reset": "соединение сброшено после TLS ClientHello — характерно для блокировки по SNI",
    "tls_eof": "сервер закрыл соединение во время TLS-рукопожатия",
    "tls_error": "ошибка TLS-рукопожатия",
    "e2e_failed": "TCP и TLS доступны, но туннель не устанавливается — вероятна блокировка протокола или сбой Xray на сервере",
    "e2e_timeout": "туннель не отвечает за отведённое время — вероятна блокировка протокола или перегрузка сервера",
    "e2e_stall": "передача данных через туннель обрывается — характерно для ограничения «16–20 КБ» на ТСПУ",
    "e2e_unavailable": "сквозная проверка невозможна",
    "e2e_unverified": "туннель не работает на всех серверах подписки, а проверить саму подписку не удалось",
    "monitor_frozen": "проверка не учтена: у сервера мониторинга проблемы с сетью",
    "internal_error": "внутренняя ошибка проверки",
}


def short_reason(code: str) -> str:
    """The reason without the explanatory tail, for lists."""
    return reason_text(code).split(" — ")[0].split(" (")[0]


def reason_text(code: str) -> str:
    return REASONS.get(code, code)


@dataclass
class Stage:
    name: str                 # dns | tcp | quic | tls | e2e
    ok: bool | None           # None = inconclusive
    code: str = "ok"
    detail: str = ""
    ms: int | None = None
    target: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = {"s": self.name, "ok": self.ok, "c": self.code}
        if self.detail:
            data["d"] = self.detail[:300]
        if self.ms is not None:
            data["ms"] = self.ms
        if self.target:
            data["t"] = self.target
        return data


@dataclass
class CheckResult:
    ok: bool | None                      # None = no trustworthy verdict
    code: str = "ok"
    stage: str = ""
    ips: list[str] = field(default_factory=list)
    good_ips: list[str] = field(default_factory=list)
    partial: bool = False
    partial_note: str = ""
    stages: list[Stage] = field(default_factory=list)
    latency_ms: int | None = None
    notes: list[str] = field(default_factory=list)
    data_probe: bool = False
    e2e_ran: bool = False

    @property
    def summary(self) -> str:
        if self.ok and self.partial:
            return f"доступен частично: {self.partial_note}"
        text = reason_text(self.code)
        detail = self.failing_detail()
        return f"{text} [{detail}]" if detail and self.ok is False else text

    def failing_detail(self) -> str:
        for stage in self.stages:
            if stage.ok is False and stage.code == self.code and stage.detail:
                return stage.detail[:160]
        return ""

    def detail(self) -> dict[str, Any]:
        return {
            "ips": self.ips, "good": self.good_ips, "partial": self.partial_note,
            "notes": self.notes, "stages": [stage.as_dict() for stage in self.stages],
        }
