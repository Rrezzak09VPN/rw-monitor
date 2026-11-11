"""The state machine in isolation: every transition, with nothing but numbers."""

import pytest

from rwmon.monitor import fsm
from rwmon.monitor.fsm import DOWN, OK, RECOVERED, SUSPECT, UNKNOWN, StateData, advance

N, M, HOLD = 3, 3, 600


def run(data: StateData, verdicts, start: int = 1000, step: int = 30):
    events, now = [], start
    for verdict in verdicts:
        transition = advance(data, verdict, now, N, M, HOLD)
        data = transition.data
        events.append(transition.event)
        now += step
    return data, events


def test_first_check_ok_is_silent_initial():
    data, events = run(StateData(), [True])
    assert data.state == OK and events == [fsm.EV_INITIAL_OK]


def test_one_or_two_failures_are_only_a_suspicion():
    data, events = run(StateData(OK), [False])
    assert data.state == SUSPECT and data.fail_streak == 1 and events == [fsm.EV_SUSPECT]
    data, events = run(data, [False])
    assert data.state == SUSPECT and data.fail_streak == 2 and events == [fsm.EV_NONE]
    data, events = run(data, [True])
    assert data.state == OK and data.fail_streak == 0 and events == [fsm.EV_CLEARED]


def test_down_exactly_at_threshold_and_keeps_first_failure_time():
    data, events = run(StateData(OK), [False, False, False], start=5000)
    assert data.state == DOWN and events == [fsm.EV_SUSPECT, fsm.EV_NONE, fsm.EV_DOWN]
    assert data.first_fail_at == 5000 and data.state_since == 5060


def test_failures_must_be_consecutive():
    data, events = run(StateData(OK), [False, False, True, False, False, True, False, False])
    assert data.state == SUSPECT and fsm.EV_DOWN not in events


def test_recovery_needs_m_consecutive_successes():
    down, _ = run(StateData(OK), [False] * 3)
    data, events = run(down, [True, True])
    assert data.state == DOWN and data.ok_streak == 2 and fsm.EV_RECOVERED not in events
    data, events = run(data, [False])
    assert data.state == DOWN and data.ok_streak == 0 and data.first_ok_at is None
    data, events = run(data, [True, True, True], start=9000)
    assert data.state == RECOVERED and events[-1] == fsm.EV_RECOVERED and data.first_ok_at == 9000


def test_recovered_settles_after_hold_or_relapses():
    recovered = StateData(RECOVERED, DOWN, state_since=1000)
    assert advance(recovered, True, 1100, N, M, HOLD).data.state == RECOVERED
    settled = advance(recovered, True, 1700, N, M, HOLD)
    assert settled.data.state == OK and settled.event == fsm.EV_SETTLED
    relapse = advance(recovered, False, 1100, N, M, HOLD)
    assert relapse.data.state == SUSPECT and relapse.data.fail_streak == 1     # a new DOWN needs full confirmation again


@pytest.mark.parametrize("state", [StateData(), StateData(OK), StateData(SUSPECT, OK, 1, fail_streak=2, first_fail_at=1),
                                   StateData(DOWN, SUSPECT, 1, ok_streak=2, first_ok_at=1), StateData(RECOVERED, DOWN, 1)])
def test_no_verdict_never_changes_anything(state):
    transition = advance(state, None, 99999, N, M, HOLD)
    assert transition.data == state and not transition.changed


def test_unknown_server_failing_goes_through_confirmation():
    data, events = run(StateData(), [False, False])
    assert data.state == SUSPECT and fsm.EV_DOWN not in events
    data, events = run(data, [False])
    assert data.state == DOWN


def test_fast_recheck_modes():
    assert fsm.fast_recheck(StateData(SUSPECT, OK, fail_streak=1)) == "suspect"
    assert fsm.fast_recheck(StateData(DOWN, SUSPECT, ok_streak=1)) == "recovering"
    assert fsm.fast_recheck(StateData(DOWN, SUSPECT)) == ""
    assert fsm.fast_recheck(StateData(OK)) == ""


def test_after_long_downtime_streaks_are_dropped():
    assert fsm.after_downtime(StateData(SUSPECT, OK, 1, fail_streak=2, first_fail_at=1), 500).state == OK
    assert fsm.after_downtime(StateData(SUSPECT, UNKNOWN, 1, fail_streak=2), 500).state == UNKNOWN
    down = fsm.after_downtime(StateData(DOWN, SUSPECT, 1, fail_streak=5, ok_streak=2, first_ok_at=9), 500)
    assert down.state == DOWN and down.ok_streak == 0 and down.first_ok_at is None
    assert fsm.after_downtime(StateData(RECOVERED, DOWN, 1), 500).state == OK
