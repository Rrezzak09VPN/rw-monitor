"""Server state machine. Pure logic: no I/O, no clock, fully unit-testable.

    OK ──fail──► SUSPECT ──N fails in a row──► DOWN ──M successes in a row──► RECOVERED
     ▲              │                            ▲                               │
     └──success─────┘                            └───────── fail ◄── SUSPECT ◄───┤ fail
     ▲                                                                           │
     └─────────────────────── observation period is over ───────────────────────┘

A check without a verdict (``ok is None``) never changes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

OK = "OK"
SUSPECT = "SUSPECT"
DOWN = "DOWN"
RECOVERED = "RECOVERED"
UNKNOWN = "UNKNOWN"
STATES = (OK, SUSPECT, DOWN, RECOVERED, UNKNOWN)

# Events produced by a transition.
EV_NONE = ""
EV_INITIAL_OK = "initial_ok"        # UNKNOWN → OK
EV_SUSPECT = "suspect"              # first failure
EV_CLEARED = "cleared"              # SUSPECT → OK, the failure was not confirmed
EV_DOWN = "down"                    # failure confirmed
EV_RECOVERED = "recovered"          # recovery confirmed
EV_SETTLED = "settled"              # RECOVERED → OK after the observation period


@dataclass(frozen=True)
class StateData:
    state: str = UNKNOWN
    prev_state: str = UNKNOWN
    state_since: int | None = None
    fail_streak: int = 0
    ok_streak: int = 0
    first_fail_at: int | None = None
    first_ok_at: int | None = None


@dataclass(frozen=True)
class Transition:
    data: StateData
    event: str = EV_NONE

    @property
    def changed(self) -> bool:
        return self.event != EV_NONE


def advance(cur: StateData, ok: bool | None, now: int, fail_threshold: int,
            recovery_threshold: int, recovered_hold: int) -> Transition:
    """Feed one check verdict into the state machine."""
    if ok is None:
        return Transition(cur)
    fail_threshold = max(1, fail_threshold)
    recovery_threshold = max(1, recovery_threshold)

    if cur.state in (OK, UNKNOWN, RECOVERED):
        if ok:
            if cur.state == UNKNOWN:
                return Transition(StateData(OK, UNKNOWN, now), EV_INITIAL_OK)
            if cur.state == RECOVERED and now - (cur.state_since or now) >= recovered_hold:
                return Transition(StateData(OK, RECOVERED, now), EV_SETTLED)
            return Transition(replace(cur, fail_streak=0, first_fail_at=None))
        data = StateData(SUSPECT, cur.state, now, fail_streak=1, first_fail_at=now)
        if fail_threshold <= 1:
            return Transition(replace(data, state=DOWN, prev_state=SUSPECT), EV_DOWN)
        return Transition(data, EV_SUSPECT)

    if cur.state == SUSPECT:
        if ok:
            return Transition(StateData(OK, SUSPECT, now), EV_CLEARED)
        streak = cur.fail_streak + 1
        if streak >= fail_threshold:
            return Transition(
                StateData(DOWN, SUSPECT, now, fail_streak=streak, first_fail_at=cur.first_fail_at or now), EV_DOWN)
        return Transition(replace(cur, fail_streak=streak, first_fail_at=cur.first_fail_at or now))

    if cur.state == DOWN:
        if not ok:
            return Transition(replace(cur, ok_streak=0, first_ok_at=None, fail_streak=cur.fail_streak + 1))
        streak = cur.ok_streak + 1
        first_ok = cur.first_ok_at or now
        if streak >= recovery_threshold:
            return Transition(StateData(RECOVERED, DOWN, now, ok_streak=streak, first_ok_at=first_ok), EV_RECOVERED)
        return Transition(replace(cur, ok_streak=streak, first_ok_at=first_ok))

    return Transition(StateData(UNKNOWN, cur.state, now))


def fast_recheck(data: StateData) -> str:
    """Which accelerated schedule applies: '' (none), 'suspect' or 'recovering'."""
    if data.state == SUSPECT:
        return "suspect"
    if data.state == DOWN and data.ok_streak > 0:
        return "recovering"
    return ""


def after_downtime(cur: StateData, now: int) -> StateData:
    """State to resume from when the monitor was not running for a long time.

    Streaks are stale: a confirmed DOWN stays DOWN, an unconfirmed suspicion is
    dropped, an observation period is considered over.
    """
    if cur.state == SUSPECT:
        back = cur.prev_state if cur.prev_state in (OK, UNKNOWN) else OK
        return StateData(back, SUSPECT, now)
    if cur.state == DOWN:
        return replace(cur, ok_streak=0, first_ok_at=None)
    if cur.state == RECOVERED:
        return StateData(OK, RECOVERED, now)
    return replace(cur, fail_streak=0, ok_streak=0, first_fail_at=None, first_ok_at=None)
