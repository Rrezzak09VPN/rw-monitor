"""Scripted replacements for the network-facing parts, to drive the monitor deterministically."""

from __future__ import annotations

import time
from typing import Callable

from rwmon.checks.results import CheckResult, Stage
from rwmon.checks.selfhealth import Health


def ok_result(ip: str = "93.184.216.34", e2e: bool = True) -> CheckResult:
    result = CheckResult(ok=True, code="ok", ips=[ip], good_ips=[ip], latency_ms=42, e2e_ran=e2e)
    result.stages = [Stage("tcp", True, "ok", "", 20, ip), Stage("tls", True, "ok", "", 30, ip)]
    if e2e:
        result.stages.append(Stage("e2e", True, "ok", "туннель работает", 42, ip))
    return result


def fail_result(code: str = "tcp_timeout", stage: str = "tcp", ip: str = "93.184.216.34",
                e2e_ran: bool = False) -> CheckResult:
    result = CheckResult(ok=False, code=code, stage=stage, ips=[ip], e2e_ran=e2e_ran)
    result.stages = [Stage(stage, False, code, "тест", 5000, ip)]
    return result


def unknown_result(code: str = "dns_unavailable") -> CheckResult:
    return CheckResult(ok=None, code=code, stage="dns")


class FakeChecker:
    """``plan[address]`` is a result, a list of results (consumed in order) or a callable."""

    def __init__(self) -> None:
        self.plan: dict[str, object] = {}
        self.default: Callable[[], CheckResult] = ok_result
        self.calls: list[tuple[str, bool]] = []

    def set(self, address: str, value: object) -> None:
        self.plan[address] = value

    def fail(self, *addresses: str, code: str = "tcp_timeout", stage: str = "tcp", e2e_ran: bool = False) -> None:
        for address in addresses:
            self.plan[address] = lambda code=code, stage=stage, e2e_ran=e2e_ran: fail_result(code, stage, e2e_ran=e2e_ran)

    def heal(self, *addresses: str) -> None:
        for address in addresses:
            self.plan.pop(address, None)

    async def check(self, target, timeouts, use_e2e: bool = True) -> CheckResult:  # noqa: ANN001
        self.calls.append((target.address, use_e2e and target.e2e))
        value = self.plan.get(target.address)
        if isinstance(value, list):
            value = value.pop(0) if value else None
        if callable(value):
            value = value()
        result = value if isinstance(value, CheckResult) else self.default()
        if not (use_e2e and target.e2e) and result.ok is False and result.stage == "e2e":
            return ok_result(e2e=False)     # without the tunnel check the lower layers pass
        return result


class FakeHealth:
    def __init__(self) -> None:
        self.foreign_ok = True
        self.ru_ok = True
        self.dns_ok = True
        self.calls = 0
        self.last = Health()

    async def check(self, force: bool = False) -> Health:
        self.calls += 1
        self.last = Health(time.monotonic(), self.foreign_ok, self.ru_ok, self.dns_ok,
                           ["зарубежные узлы: тест", "российские узлы: тест", "DNS: тест"])
        return self.last


class FakeE2E:
    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.version = "Xray test"
        self.problem = "" if available else "исполняемый файл Xray не найден (тест)"

    async def probe_binary(self) -> bool:
        return self.available
