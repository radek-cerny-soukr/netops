import pytest

from netops_core import session


class ChildExit(BaseException):
    pass


def test_spawn_parent_returns_pty_without_exec(monkeypatch):
    monkeypatch.setattr(session.pty, "fork", lambda: (73, 91))
    monkeypatch.setattr(session.os, "execvpe", lambda *args: pytest.fail("parent executed"))
    monkeypatch.setattr(session.os, "_exit", lambda *args: pytest.fail("parent exited"))
    assert session._spawn(["owned-program", "arg"], {"OWNED": "value"}) == (73, 91)


@pytest.mark.parametrize("failure", [None, FileNotFoundError("owned-program"), PermissionError("owned-program")])
def test_spawn_child_exits_127_even_when_exec_fails_or_returns(monkeypatch, failure):
    call = ["owned-program", "arg"]
    env = {"OWNED": "value"}
    observed = []
    monkeypatch.setattr(session.pty, "fork", lambda: (0, 91))

    def execute(program, arguments, environment):
        observed.append((program, arguments, environment))
        if failure is not None:
            raise failure

    def leave(code):
        observed.append(code)
        raise ChildExit()

    monkeypatch.setattr(session.os, "execvpe", execute)
    monkeypatch.setattr(session.os, "_exit", leave)
    with pytest.raises(ChildExit):
        session._spawn(call, env)
    assert observed == [("owned-program", call, env), 127]


def test_spawn_propagates_fork_error_without_exec(monkeypatch):
    failure = OSError("pty unavailable")

    def fork():
        raise failure

    monkeypatch.setattr(session.pty, "fork", fork)
    monkeypatch.setattr(session.os, "execvpe", lambda *args: pytest.fail("executed after fork error"))
    with pytest.raises(OSError) as refused:
        session._spawn(["owned-program"], {})
    assert refused.value is failure
