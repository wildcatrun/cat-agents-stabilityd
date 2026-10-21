"""Bounded per-component collector isolation for stabilityd snapshots."""

from __future__ import annotations

import contextlib
import json
import os
import selectors
import signal
import subprocess
import sys
import time
import ctypes
from typing import Any, Callable, Mapping, Sequence


def _waitid_unreaped(pid: int) -> tuple[bool, int, int, int]:
    """Return (available, child_pid, si_code, si_status) without reaping."""
    if hasattr(os, "waitid") and all(hasattr(os, key) for key in ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
        try:
            info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except OSError:
            return True, -1, -1, -1
        if info is None:
            return True, 0, 0, 0
        return True, int(info.si_pid or 0), int(info.si_code or 0), int(info.si_status or 0)
    if sys.platform == "darwin" and hasattr(os, "WNOWAIT"):
        # CPython may omit os.waitid on Darwin although libc provides it.
        # Darwin siginfo_t places signo/errno/code/pid/uid/status at offsets
        # 0/4/8/12/16/20; keep this isolated and fail closed on any libc error.
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            waitid = libc.waitid
            waitid.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
            waitid.restype = ctypes.c_int
            info = ctypes.create_string_buffer(128)
            flags = 0x00000004 | 0x00000001 | int(os.WNOWAIT)  # WEXITED | WNOHANG | WNOWAIT
            if waitid(1, pid, ctypes.byref(info), flags) != 0:
                return True, -1, -1, ctypes.get_errno()
            child_pid = ctypes.c_int.from_buffer(info, 12).value
            code = ctypes.c_int.from_buffer(info, 8).value
            status = ctypes.c_int.from_buffer(info, 20).value
            return True, child_pid, code, status
        except (AttributeError, OSError, ValueError):
            return False, 0, 0, 0
    return False, 0, 0, 0


def _process_group_members(pgid: int) -> set[tuple[int, str]] | None:
    """Enumerate (pid, state) for a process group; None means unknown."""
    members: set[tuple[int, str]] = set()
    if sys.platform.startswith("linux"):
        deadline = time.monotonic() + 0.5
        visited = 0
        try:
            entries = os.scandir("/proc")
        except OSError:
            return None
        with entries:
            for entry in entries:
                visited += 1
                if visited > 100_000 or time.monotonic() >= deadline:
                    return None
                if not entry.name.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry.name}/stat", "r", encoding="ascii") as stat_file:
                        raw = stat_file.read(16_384)
                except FileNotFoundError:
                    continue
                except OSError:
                    return None
                if time.monotonic() >= deadline:
                    return None
                end = raw.rfind(")")
                if end < 0:
                    return None
                fields = raw[end + 2:].split()  # state, ppid, pgrp, ...
                if len(fields) < 3:
                    return None
                try:
                    if int(fields[2]) == pgid:
                        members.add((int(entry.name), fields[0]))
                except ValueError:
                    return None
        return members
    if sys.platform == "darwin":
        proc: subprocess.Popen[bytes] | None = None
        selector = selectors.DefaultSelector()
        output = bytearray()
        try:
            proc = subprocess.Popen(
                ["/bin/ps", "-axo", "pid=,pgid=,stat="], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
                start_new_session=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            assert proc.stdout is not None
            selector.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 1.0
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("process listing timed out")
                if not selector.select(remaining):
                    continue
                chunk = os.read(proc.stdout.fileno(), min(65_536, 2_000_001 - len(output)))
                if not chunk:
                    selector.unregister(proc.stdout)
                    continue
                output.extend(chunk)
                if len(output) > 2_000_000:
                    raise ValueError("process listing exceeded output bound")
            if proc.wait(timeout=max(0.0, deadline - time.monotonic())) != 0:
                return None
        except (OSError, subprocess.TimeoutExpired, TimeoutError, ValueError):
            if proc is not None and proc.returncode is None:
                with contextlib.suppress(OSError):
                    os.killpg(proc.pid, signal.SIGKILL)
                with contextlib.suppress(Exception):
                    proc.wait(timeout=0.5)
            return None
        finally:
            selector.close()
            if proc is not None and proc.stdout is not None:
                proc.stdout.close()
        try:
            for line in output.decode("ascii").splitlines():
                fields = line.split()
                if len(fields) != 3:
                    return None
                pid_value, group_value, state = int(fields[0]), int(fields[1]), fields[2]
                if group_value == pgid:
                    members.add((pid_value, state))
        except (UnicodeDecodeError, ValueError):
            return None
        return members
    return None


def _live_group_members(members: set[tuple[int, str]], leader_pid: int) -> set[int]:
    return {pid for pid, state in members if pid != leader_pid and state[:1] not in {"Z", "X"}}


def run_component_probe(
    name: str,
    collector: Callable[[], Any],
    fallback: Mapping[str, Any],
    *,
    source: str,
    max_output_bytes: int = 1_000_000,
    budget_ms: int = 60_000,
    monotonic: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """Catch component failures and discard over-budget/oversize output.

    The budget is an acceptance bound checked on return. Individual subprocess
    probes must still set their own hard timeout; this helper never spawns a
    detached thread that could continue writing after the component failed.
    """
    clock = monotonic or time.monotonic
    if type(max_output_bytes) is not int or max_output_bytes <= 0 or type(budget_ms) is not int or budget_ms <= 0:
        return {
            "data": dict(fallback),
            "probe": {
                "component": name, "status": "error", "source": source, "coverage": False,
                "durationMs": 0, "budgetMs": budget_ms, "maxOutputBytes": max_output_bytes,
                "errorClass": "InvalidBudget",
            },
        }
    started = clock()
    status = "ok"
    error_class = None
    value: Any = None
    try:
        value = collector()
        if not isinstance(value, Mapping):
            status, error_class = "error", "InvalidCollectorResult"
        else:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
            if len(encoded) > max_output_bytes:
                status, error_class = "degraded", "OutputBudgetExceeded"
    except Exception as exc:
        status, error_class = "error", type(exc).__name__
    duration_ms = max(0, int((clock() - started) * 1000))
    if status == "ok" and duration_ms > budget_ms:
        status, error_class = "degraded", "ProbeBudgetExceeded"
    covered = status == "ok"
    return {
        "data": dict(value) if covered else dict(fallback),
        "probe": {
            "component": name,
            "status": status,
            "source": source,
            "coverage": covered,
            "durationMs": duration_ms,
            "budgetMs": budget_ms,
            "maxOutputBytes": max_output_bytes,
            "errorClass": error_class,
        },
    }


def run_component_probe_hard(
    name: str,
    command: Sequence[str],
    fallback: Mapping[str, Any],
    *,
    source: str,
    max_output_bytes: int = 1_000_000,
    max_stderr_bytes: int = 16_384,
    budget_ms: int = 60_000,
    terminate_grace_ms: int = 250,
    env: Mapping[str, str] | None = None,
    observer_tick: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Run a fresh, POSIX process-group worker with a hard wall-clock deadline.

    The worker command must be an explicit argv sequence (never a shell string)
    and emit one JSON object on stdout with ``data`` (mapping) and ``findings``
    (list). Stdout and stderr are drained incrementally and bounded in memory;
    stderr is never returned. Timeout/failure/invalid output returns fallback
    and no child findings. This supervises only the child process boundary; it
    does not make arbitrary inherited Python callables interruptible.
    """
    started = time.monotonic()
    observer_error = None
    def observe():
        nonlocal observer_error
        if observer_tick is not None:
            try: observer_tick()
            except Exception as exc: observer_error = type(exc).__name__

    def result(status: str, error_class: str, duration_ms: int, *, data: Mapping[str, Any] | None = None,
               findings: list[Any] | None = None, fatal: bool = False,
               leader_reaped: bool = False, cache_updates: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return {
            "data": dict(data) if data is not None else dict(fallback),
            "findings": list(findings or []) if data is not None else [],
            "cacheUpdates": dict(cache_updates or {}) if data is not None else {},
            "probe": {
                "component": name, "status": status, "source": source,
                "observerErrorClass": observer_error,
                "coverage": status == "ok", "durationMs": duration_ms,
                "budgetMs": budget_ms, "maxOutputBytes": max_output_bytes,
                "errorClass": None if status == "ok" else error_class,
                "isolation": "posix-process-group",
                "fatal": fatal,
                "leaderReaped": leader_reaped,
                # This observation is process-group scoped and is not an
                # atomic proof against deliberately escaped descendants.
                "noLiveGroupMemberObserved": False if fatal else None,
            },
        }

    if os.name != "posix":
        return result("error", "UnsupportedPlatform", 0)
    if (not isinstance(command, Sequence) or isinstance(command, (str, bytes)) or not command
            or any(not isinstance(part, str) or not part for part in command)
            or type(max_output_bytes) is not int or max_output_bytes <= 0
            or type(max_stderr_bytes) is not int or max_stderr_bytes <= 0
            or type(budget_ms) is not int or budget_ms <= 0
            or type(terminate_grace_ms) is not int or terminate_grace_ms < 0
            or (env is not None and (not isinstance(env, Mapping) or any(
                not isinstance(key, str) or not key or "=" in key or "\0" in key
                or not isinstance(value, str) or "\0" in value
                for key, value in env.items()
            )))):
        return result("error", "InvalidProbeRequest", 0)

    try:
        proc = subprocess.Popen(
            list(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=True,
            env=dict(env) if env is not None else {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except Exception:
        return result("error", "ProbeStartFailed", 0)

    assert proc.stdout is not None and proc.stderr is not None
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max_output_bytes, "stderr": max_stderr_bytes}
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    deadline = started + budget_ms / 1000
    error_class: str | None = None
    leader_succeeded = False
    try:
        while selector.get_map():
            observe()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error_class = "ProbeTimeout"
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                try:
                    chunk = os.read(key.fileobj.fileno(), min(8192, limits[key.data] + 1))
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                bucket = buffers[key.data]
                bucket.extend(chunk)
                if len(bucket) > limits[key.data]:
                    error_class = "OutputBudgetExceeded"
                    break
            if error_class:
                break
        if error_class is None:
            # Observe exit without reaping the leader. Keeping its PID/PGID
            # reserved lets finally clean descendants even if they closed both
            # inherited pipes before the worker exited.
            while time.monotonic() < deadline:
                observe()
                available, child_pid, exit_code, exit_status = _waitid_unreaped(proc.pid)
                if not available:
                    error_class = "SafeWaitUnavailable"
                    break
                if child_pid < 0:
                    error_class = "SafeWaitFailed"
                    break
                if child_pid:
                    if exit_code != getattr(os, "CLD_EXITED", 1) or exit_status != 0:
                        error_class = "ProbeFailed"
                    else:
                        leader_succeeded = True
                    break
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
            else:
                error_class = "ProbeTimeout"
    finally:
        selector.close()
        cleanup_failed = False
        cleanup_failure_class = None
        termination_verified = False
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                # The leader may already be a zombie and the group may have no
                # signalable members; the following bounded scans decide that.
                # If live descendants remain, SIGKILL must still succeed or the
                # cleanup closes as fatal below.
                pass
            except OSError:
                cleanup_failed = True
                cleanup_failure_class = "ProcessGroupTerm"
            if terminate_grace_ms:
                time.sleep(terminate_grace_ms / 1000)
            kill_sent = False
            empty_scans = 0
            verify_deadline = time.monotonic() + max(1.0, terminate_grace_ms / 1000)
            while time.monotonic() < verify_deadline:
                members = _process_group_members(proc.pid)
                if members is None:
                    cleanup_failed = True
                    cleanup_failure_class = "ProcessGroupEnumerationFailed"
                    if not kill_sent:
                        with contextlib.suppress(OSError):
                            os.killpg(proc.pid, signal.SIGKILL)
                        kill_sent = True
                    break
                live_members = _live_group_members(members, proc.pid)
                available, child_pid, _, _ = _waitid_unreaped(proc.pid)
                leader_exited = bool(available and child_pid == proc.pid)
                if live_members or not leader_exited:
                    empty_scans = 0
                    if not kill_sent:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        except (PermissionError, OSError):
                            cleanup_failed = True
                            cleanup_failure_class = "ProcessGroupKill"
                            break
                        kill_sent = True
                else:
                    empty_scans += 1
                    if empty_scans >= 2:
                        termination_verified = True
                        break
                time.sleep(0.025)
            if not termination_verified and not cleanup_failure_class:
                cleanup_failed = True
                cleanup_failure_class = "ProcessGroupTerminationUnverified"
            try:
                proc.wait(timeout=max(0.25, terminate_grace_ms / 1000))
            except subprocess.TimeoutExpired:
                cleanup_failed = True
                cleanup_failure_class = "WorkerReapTimeout"
        elif error_class:
            cleanup_failed = True
            cleanup_failure_class = "SafeGroupCleanupUnavailable"
        if cleanup_failed:
            error_class = "ProbeCleanupFailed"
        for stream in (proc.stdout, proc.stderr):
            stream.close()

    duration_ms = max(0, int((time.monotonic() - started) * 1000))
    if error_class:
        fatal = error_class == "ProbeCleanupFailed"
        output = result("error" if fatal else ("degraded" if error_class in {"ProbeTimeout", "OutputBudgetExceeded"} else "error"),
                        error_class, duration_ms, fatal=fatal, leader_reaped=proc.returncode is not None)
        output["probe"]["noLiveGroupMemberObserved"] = termination_verified and not fatal
        output["probe"]["leaderReaped"] = proc.returncode is not None
        if cleanup_failure_class:
            output["probe"]["cleanupFailureClass"] = cleanup_failure_class
        return output
    try:
        def reject_nonfinite(value: str) -> None:
            raise ValueError("nonfinite number is not valid worker evidence")
        envelope = json.loads(buffers["stdout"].decode("utf-8"), parse_constant=reject_nonfinite)
        data, findings = envelope["data"], envelope["findings"]
        cache_updates = envelope.get("cacheUpdates") or {}
        if not isinstance(data, Mapping) or not isinstance(findings, list) or not isinstance(cache_updates, Mapping) or any(
            not isinstance(item, Mapping) for item in findings
        ):
            raise ValueError("invalid result envelope")
    except Exception:
        invalid = result("error", "InvalidWorkerResult", duration_ms, leader_reaped=proc.returncode is not None)
        invalid["probe"]["noLiveGroupMemberObserved"] = termination_verified
        return invalid
    output = result("ok", "", duration_ms, data=data, findings=findings, cache_updates=cache_updates)
    output["probe"]["noLiveGroupMemberObserved"] = termination_verified
    output["probe"]["leaderReaped"] = proc.returncode is not None
    return output
