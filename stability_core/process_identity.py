"""Linux process-instance identity and pidfd-bound signalling helpers."""

from __future__ import annotations

import hashlib
import os
import signal
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple


IDENTITY_FIELDS = ("pid", "starttime", "uid", "euid", "bootId", "cmdlineDigest", "cgroupDigest")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_process_identity(pid: int, proc_root: Path = Path("/proc")) -> Dict[str, Any]:
    """Return a fail-closed identity for one Linux process instance."""
    identity: Dict[str, Any] = {"status": "unknown", "pid": pid}
    if pid <= 1:
        identity["reason"] = "unsafe-pid"
        return identity
    try:
        stat = (proc_root / str(pid) / "stat").read_text(encoding="utf-8")
        close = stat.rfind(")")
        open_ = stat.find("(")
        if open_ < 0 or close <= open_:
            raise ValueError("malformed-stat-comm")
        suffix = stat[close + 1 :].split()
        # suffix begins with field 3 (state); starttime is field 22.
        if len(suffix) < 20:
            raise ValueError("short-stat")
        starttime = int(suffix[19])
        status_text = (proc_root / str(pid) / "status").read_text(encoding="utf-8")
        uid_line = next((line for line in status_text.splitlines() if line.startswith("Uid:")), "")
        uid_fields = uid_line.split()[1:]
        if len(uid_fields) < 2:
            raise ValueError("missing-uid")
        cmdline = (proc_root / str(pid) / "cmdline").read_bytes()
        cgroup = (proc_root / str(pid) / "cgroup").read_bytes()
        boot_id = (proc_root / "sys" / "kernel" / "random" / "boot_id").read_text(encoding="ascii").strip()
        if not cmdline or not cgroup or not boot_id or starttime <= 0:
            raise ValueError("incomplete-identity")
        identity.update(
            status="known",
            starttime=starttime,
            uid=int(uid_fields[0]),
            euid=int(uid_fields[1]),
            bootId=boot_id,
            cmdlineDigest=_digest(cmdline),
            cgroupDigest=_digest(cgroup),
        )
    except (OSError, UnicodeError, ValueError, StopIteration) as exc:
        identity["reason"] = f"identity-read-failed:{type(exc).__name__}"
    return identity


def identities_match(expected: Dict[str, Any], current: Dict[str, Any]) -> Tuple[bool, str]:
    if expected.get("status") != "known" or current.get("status") != "known":
        return False, "identity-unknown"
    for field in IDENTITY_FIELDS:
        if expected.get(field) is None or current.get(field) is None:
            return False, f"identity-field-missing:{field}"
        if type(expected.get(field)) is not type(current.get(field)) or expected.get(field) != current.get(field):
            return False, f"identity-mismatch:{field}"
    return True, "identity-match"


def terminate_process_instance(
    expected: Dict[str, Any],
    *,
    proc_root: Path = Path("/proc"),
    identity_reader: Callable[[int, Path], Dict[str, Any]] = read_process_identity,
    pidfd_open: Optional[Callable[[int, int], int]] = getattr(os, "pidfd_open", None),
    pidfd_send_signal: Optional[Callable[..., Any]] = getattr(signal, "pidfd_send_signal", None),
    close_fd: Callable[[int], Any] = os.close,
    sleep: Callable[[float], Any] = time.sleep,
    postcheck_attempts: int = 3,
    postcheck_interval: float = 0.05,
) -> Dict[str, Any]:
    """SIGTERM exactly the captured instance, or fail closed without os.kill."""
    try:
        pid = int(expected.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    if pid <= 1 or expected.get("status") != "known":
        return {"result": "blocked", "reason": "identity-unknown"}
    if pidfd_open is None or pidfd_send_signal is None:
        return {"result": "blocked", "reason": "pidfd-unavailable"}

    current = identity_reader(pid, proc_root)
    matched, reason = identities_match(expected, current)
    if not matched:
        return {"result": "blocked", "reason": f"pre-signal-{reason}"}
    try:
        pidfd = pidfd_open(pid, 0)
    except ProcessLookupError:
        return {"result": "succeeded", "reason": "already-exited"}
    except (OSError, TypeError) as exc:
        return {"result": "blocked", "reason": "pidfd-open-failed", "errorClass": type(exc).__name__}
    result: Dict[str, Any] = {}
    try:
        current = identity_reader(pid, proc_root)
        matched, reason = identities_match(expected, current)
        if not matched:
            result = {"result": "blocked", "reason": f"post-pidfd-{reason}"}
            return result
        try:
            pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
        except ProcessLookupError:
            result = {"result": "succeeded", "reason": "exited-before-signal"}
            return result
        except OSError as exc:
            result = {"result": "failed", "reason": "pidfd-signal-failed", "error": type(exc).__name__}
            return result

        for attempt in range(max(1, postcheck_attempts)):
            try:
                observed = identity_reader(pid, proc_root)
            except Exception as exc:
                result = {"result": "uncertain", "reason": "post-signal-identity-read-failed",
                          "error": type(exc).__name__, "signal": "SIGTERM"}
                return result
            if observed.get("status") != "known":
                # Only disappearance of the PID directory proves exit. A partial
                # read failure while it still exists remains uncertain.
                if not (proc_root / str(pid)).exists():
                    result = {"result": "succeeded", "reason": "process-exited", "signal": "SIGTERM"}
                    return result
            else:
                same, mismatch = identities_match(expected, observed)
                if not same:
                    if any(observed.get(key) != expected.get(key) for key in ("bootId", "pid", "starttime")):
                        result = {"result": "succeeded", "reason": "process-birth-changed", "signal": "SIGTERM"}
                        return result
                    result = {"result": "uncertain", "reason": mismatch, "signal": "SIGTERM"}
                    return result
            if attempt + 1 < max(1, postcheck_attempts):
                try:
                    sleep(postcheck_interval)
                except Exception as exc:
                    result = {"result": "uncertain", "reason": "postcheck-wait-failed",
                              "error": type(exc).__name__, "signal": "SIGTERM"}
                    return result
        result = {"result": "uncertain", "reason": "sigterm-postcheck-still-same-instance", "signal": "SIGTERM"}
        return result
    finally:
        try:
            close_fd(pidfd)
        except Exception as exc:
            # Cleanup failure must not erase signal/postcheck evidence or abort a lane.
            result["fdCloseError"] = type(exc).__name__
            if result.get("result") == "succeeded":
                result["result"] = "uncertain"
                result["reason"] = "pidfd-close-failed-after-signal"
