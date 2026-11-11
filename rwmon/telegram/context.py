"""Everything a handler may need, passed around as one object."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..cheburcheck.service import CheburcheckService
    from ..config import Config
    from ..db.database import Database
    from ..maintenance import Maintenance
    from ..monitor.alerts import Alerts
    from ..monitor.service import Monitor
    from ..outbox import Outbox
    from ..settings import Settings
    from ..subscription.service import SubscriptionService
    from .bot import BotManager
    from .notifier import Notifier


@dataclass
class Ctx:
    config: "Config"
    db: "Database"
    settings: "Settings"
    subs: "SubscriptionService"
    monitor: "Monitor"
    cc: "CheburcheckService"
    alerts: "Alerts"
    outbox: "Outbox"
    botman: "BotManager"
    notifier: "Notifier"
    maintenance: "Maintenance"
