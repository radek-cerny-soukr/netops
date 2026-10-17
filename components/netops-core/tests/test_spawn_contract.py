import pytest

from netops_core import session


class ChildExit(BaseException):
    pass


def test_spawn_parent_returns_pty_without_exec(monkeypatch):
    monkeypatch.setattr(session.pty, "fork", lambda: (73, 91))
    monkeypatch.setattr(session.os, "execve", lambda *args: pytest.fail("parent executed"))
    monkeypatch.setattr(session.os, "_exit", lambda *args: pytest.fail("parent exited"))
    assert session._spawn(["owned-program", "arg"], {"OWNED": "value"}) == (73, 91)


@pytest.mark.parametrize("failure", [None, FileNotFoundError("owned-program"), PermissionError("owned-program")])
def test_spawn_child_exits_127_even_when_exec_fails_or_returns(monkeypatch, failure):
    call = ["owned-program", "arg"]
    env = {"OWNED": "value", "PATH": "/owned"}
    observed = []
    monkeypatch.setattr(session.pty, "fork", lambda: (0, 91))

    def execute(program, arguments, environment):
        observed.append((program, arguments, environment))
        if failure is not None:
            raise failure

    def leave(code):
        observed.append(code)
        raise ChildExit()

    monkeypatch.setattr(session.os, "execve", execute)
    monkeypatch.setattr(session.os, "_exit", leave)
    with pytest.raises(ChildExit):
        session._spawn(call, env)
    assert observed == [(b"/owned/owned-program", call, env), 127]


def test_spawn_propagates_fork_error_without_exec(monkeypatch):
    failure = OSError("pty unavailable")

    def fork():
        raise failure

    monkeypatch.setattr(session.pty, "fork", fork)
    monkeypatch.setattr(session.os, "execve", lambda *args: pytest.fail("executed after fork error"))
    with pytest.raises(OSError) as refused:
        session._spawn(["owned-program"], {})
    assert refused.value is failure


@pytest.mark.parametrize("program,env,expected", [
    ("owned-program", {"PATH": "/first:relative::/last"},
     [b"/first/owned-program", b"relative/owned-program", b"owned-program", b"/last/owned-program"]),
    (b"owned-program", {b"PATH": b"/first:relative-\xff::/last"},
     [b"/first/owned-program", b"relative-\xff/owned-program", b"owned-program", b"/last/owned-program"]),
    ("owned-program", {"PATH": ""}, [b"owned-program"]),
    (b"owned-program", {b"PATH": b""}, [b"owned-program"]),
    ("owned-program", {}, None),
    ("/explicit/owned-program", {"PATH": "/ignored"}, ["/explicit/owned-program"]),
    ("relative/owned-program", {"PATH": "/ignored"}, ["relative/owned-program"]),
    (b"/explicit/owned-program", {b"PATH": b"/ignored"}, [b"/explicit/owned-program"]),
    (b"relative/owned-program", {}, [b"relative/owned-program"]),
])
def test_spawn_prepares_path_candidates_before_fork_and_keeps_argv_env(monkeypatch, program, env, expected):
    call = [program, "arg"]
    if expected is None:
        expected = [session.os.fsencode(session.os.path.join(directory, "owned-program"))
                    for directory in session.os.defpath.split(session.os.pathsep)]
    monkeypatch.setenv("PATH", "/parent-path-must-not-be-used")
    real_paths = session.os.get_exec_path
    events, observed = [], []
    def paths(environment):
        assert not events
        assert environment is env
        events.append("paths")
        return real_paths(environment)
    def fork():
        events.append("fork")
        return 0, 91
    def execute(executable, arguments, environment):
        assert events[-1] == "fork"
        assert arguments is call and environment is env
        observed.append(executable)
        raise FileNotFoundError("synthetic missing program")
    def leave(code):
        observed.append(code)
        raise ChildExit()
    monkeypatch.setattr(session.os, "get_exec_path", paths)
    monkeypatch.setattr(session.pty, "fork", fork)
    monkeypatch.setattr(session.os, "execve", execute)
    monkeypatch.setattr(session.os, "execvpe", lambda *args: pytest.fail("child searched PATH"))
    monkeypatch.setattr(session.os, "_exit", leave)
    with pytest.raises(ChildExit):
        session._spawn(call, env)
    assert observed == [*expected, 127]
    assert events == (["fork"] if session.os.path.dirname(program) else ["paths", "fork"])


def test_spawn_continues_after_exec_errors_and_stops_if_exec_returns(monkeypatch):
    call = ["owned-program", "arg"]
    env = {"PATH": "/denied:/not-directory:/bad-format:/working:/not-reached"}
    observed = []
    failures = [PermissionError("synthetic denied"), NotADirectoryError("synthetic not-directory"),
                OSError("synthetic executable format")]
    monkeypatch.setattr(session.pty, "fork", lambda: (0, 91))
    def execute(executable, arguments, environment):
        assert arguments is call and environment is env
        observed.append(executable)
        if failures:
            raise failures.pop(0)
    def leave(code):
        observed.append(code)
        raise ChildExit()
    monkeypatch.setattr(session.os, "execve", execute)
    monkeypatch.setattr(session.os, "execvpe", lambda *args: pytest.fail("child searched PATH"))
    monkeypatch.setattr(session.os, "_exit", leave)
    with pytest.raises(ChildExit):
        session._spawn(call, env)
    assert observed == [b"/denied/owned-program", b"/not-directory/owned-program",
                        b"/bad-format/owned-program", b"/working/owned-program", 127]
