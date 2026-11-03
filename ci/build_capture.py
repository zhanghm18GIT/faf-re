"""Dedicated bounded text-build capture. No action occurs on import.
Never used for binary Git output. All process control targets our own spawned child.
Windows process-tree termination is reported, not claimed independently verified.
"""
from __future__ import annotations
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time

NINJA_STATUS = "FAF_NINJA [%f/%t running=%r elapsed=%e] "
STATUS_RE = re.compile(rb"FAF_NINJA \[(\d+)/(\d+) running=(\d+) elapsed=([0-9.]+)\]")
# These are reservations, not predictions. No existing test/child cap is reduced.
# Local-I/O allocations below are cooperative proposals, not implemented OS deadlines.
COMPLETION_RESERVE = {
    "actual_links_and_hash_checks": 120,
    "two_test_discoveries": 240,
    "math_ctest": 420,
    "coroutine_ctest": 210,
    "four_post_test_git_reads": 1200,
    "six_pe_inspections": 720,
    "source_material_zip_and_validation": 480,
    "upload": 330,
    "final_cleanup": 60,
    "build_termination_and_capture": 30,
}
DIAGNOSTIC_RESERVE = 150  # 30 child/capture +60 successful-log checks +60 workspace cleanup; I/O is cooperative.
DIAGNOSTIC_BUILD_CAP = 600


def build_budget(mode, remaining_seconds):
    if mode == "diagnostic_only":
        reserve = DIAGNOSTIC_RESERVE
        cap = DIAGNOSTIC_BUILD_CAP
    elif mode == "completion":
        reserve = sum(COMPLETION_RESERVE.values())
        cap = 2700
    else:
        raise ValueError("Unreviewed execution mode")
    available = int(remaining_seconds) - reserve
    if available < 30:
        raise ValueError("No coherent build window after downstream reservation: "
                         + json.dumps({"mode": mode, "remaining": int(remaining_seconds), "reserve": reserve}))
    return min(cap, available), reserve


def safe_text(value, aliases=()):
    text = str(value)
    for original, replacement in sorted(aliases, key=lambda x: len(str(x[0])), reverse=True):
        # Match slash variants, including compiler output's case-insensitive Windows paths.
        pattern = "".join(r"[\\/]" if ch in "/\\" else re.escape(ch) for ch in str(original))
        text = re.sub(pattern, lambda _: replacement, text, flags=re.I)
    return "".join(ch if ch in "\n\t" or ord(ch) >= 32 else "?" for ch in text)


def resource_sample(proc):
    """Parent-process metrics only; never label these compiler-tree CPU or RAM."""
    result = {"scope": "owned_cmake_parent_only_not_compiler_tree"}
    if os.name != "nt":
        result["status"] = "UNAVAILABLE_ON_THIS_PLATFORM"
        return result
    try:
        from ctypes import wintypes
        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", wintypes.DWORD), ("load", wintypes.DWORD)] + [
                (n, ctypes.c_ulonglong) for n in ["total_phys", "avail_phys", "total_page", "avail_page", "total_virtual", "avail_virtual", "avail_extended"]]
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (n, ctypes.c_size_t) for n in ["peak_working", "working", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile"]]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MemoryStatus)]
        kernel.GlobalMemoryStatusEx.restype = wintypes.BOOL
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.GetProcessTimes.restype = wintypes.BOOL
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        memory = MemoryStatus(); memory.length = ctypes.sizeof(memory)
        if kernel.GlobalMemoryStatusEx(ctypes.byref(memory)):
            result.update(available_ram_bytes=memory.avail_phys, total_ram_bytes=memory.total_phys)
        counters = Counters(); counters.cb = ctypes.sizeof(counters)
        handle = wintypes.HANDLE(int(proc._handle))
        if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            result["parent_working_set_bytes"] = counters.working
        times = [wintypes.FILETIME() for _ in range(4)]
        if kernel.GetProcessTimes(handle, *(ctypes.byref(x) for x in times)):
            ticks = lambda t: (t.dwHighDateTime << 32) | t.dwLowDateTime
            result["parent_cpu_seconds"] = (ticks(times[2]) + ticks(times[3])) / 10000000
        result["status"] = "SAMPLED" if len(result) > 1 else "UNAVAILABLE"
    except Exception as exc:
        result.update(status="UNAVAILABLE", error_type=type(exc).__name__)
    return result


def terminate_owned(proc, control_log):
    """Bounded best effort. A taskkill return code is evidence, not a tree proof."""
    result = {"descendant_shutdown": "NOT_INDEPENDENTLY_VERIFIED"}
    if proc.pid == os.getpid():
        return dict(result, state="REFUSED_HOST_PID")
    if proc.poll() is not None:
        return dict(result, state="PARENT_ALREADY_EXITED", parent_reaped=True)
    try:
        if os.name == "nt":
            # Use a regular file, never communicate() on a potentially inherited pipe.
            with Path(control_log).open("wb") as out:
                completed = subprocess.run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                    stdout=out, stderr=subprocess.STDOUT, timeout=15, check=False)
            result["taskkill_exit"] = completed.returncode
            with Path(control_log).open("rb") as f:
                f.seek(max(0, Path(control_log).stat().st_size - 4096))
                result["taskkill_tail"] = f.read(4096).decode("utf-8", errors="replace")
        else:
            # POSIX fixture route: Popen below creates this child's own session.
            os.killpg(proc.pid, signal.SIGKILL)
            result["owned_process_group_kill_requested"] = True
    except Exception as exc:
        result["tree_termination_error"] = type(exc).__name__
    if proc.poll() is None:
        try:
            proc.kill()
            result["parent_kill_requested"] = True
        except Exception as exc:
            result["parent_kill_error"] = type(exc).__name__
    try:
        proc.wait(timeout=5)
        result["parent_reaped"] = True
    except Exception as exc:
        result.update(parent_reaped=False, parent_reap_error=type(exc).__name__)
    result["state"] = "TERMINATION_ATTEMPT_RECORDED"
    return result


def ninja_summary(path, aliases=()):
    path = Path(path)
    limit = 16 * 1024 * 1024
    if not path.is_file():
        return {"state": "MISSING", "completed_entries": 0}
    if path.stat().st_size > limit:
        return {"state": "TOO_LARGE_TO_INSPECT", "completed_entries": None}
    count, longest = 0, []
    try:
        # The child might still be writing after uncertain cleanup. Enforce the
        # read ceiling itself, not merely the potentially stale size above.
        with path.open("rb") as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            return {"state": "TOO_LARGE_TO_INSPECT", "completed_entries": None}
        partial = bool(data and not data.endswith(b"\n"))
        lines = data.split(b"\n")
        if partial:
            lines.pop()  # Do not count an unfinished trailing record.
        if not lines or lines[0].rstrip(b"\r") not in {b"# ninja log v5", b"# ninja log v6"}:
            return {"state": "UNSUPPORTED_FORMAT", "completed_entries": None}
        for raw in lines[1:]:
            fields = raw.decode("utf-8", errors="replace").rstrip("\r").split("\t")
            if len(fields) != 5:
                continue
            start, end = int(fields[0]), int(fields[1])
            if end < start:
                continue
            count += 1
            longest.append({"duration_ms": end - start, "output": safe_text(fields[3], aliases)[-240:]})
            longest.sort(key=lambda x: x["duration_ms"], reverse=True)
            del longest[10:]
        return {"state": "READ", "format_version": int(lines[0].rstrip(b"\r")[-1:]), "completed_entries": count, "longest_completed_outputs": longest,
                "snapshot_only": True, "unfinished_trailing_record_ignored": partial,
                "note": "Output rows, not unique commands; multi-output edges repeat durations. Incomplete commands have no completed duration."}
    except (OSError, ValueError) as exc:
        return {"state": "UNREADABLE", "error_type": type(exc).__name__}


def run_build(args, *, cwd, env, log_path, timeout, emit, aliases=(),
              max_log_bytes=128 * 1024 * 1024, tail_bytes=16384,
              sample_interval=30, progress_interval=5, poll_interval=0.1,
              terminate=terminate_owned, sampler=resource_sample):
    """Capture exact bytes to a hard-size-capped file, with bounded live metadata.
    A daemon reader uses read1(), not read-to-EOF or readline(). Once the disk cap
    is hit it drains/discards while the controller terminates the owned child.
    A stuck reader/held inherited pipe is an explicit non-success outcome.
    """
    if timeout <= 0 or max_log_bytes <= 0 or tail_bytes <= 0:
        raise ValueError("Positive capture bounds required before process launch")
    if min(sample_interval, progress_interval, poll_interval) <= 0:
        raise ValueError("Positive reporting intervals required")
    log_path = Path(log_path)
    started = time.monotonic()
    state = {"total_bytes": 0, "retained_bytes": 0, "tail": b"", "failure": None, "last_status": None}
    lock, done = threading.Lock(), threading.Event()
    child_env = dict(env)
    child_env["NINJA_STATUS"] = NINJA_STATUS
    opts = dict(cwd=str(cwd), env=child_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if os.name == "nt":
        opts["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        opts["start_new_session"] = True
    proc = None
    reader = None
    reader_started = False
    outcome = "CAPTURE_FAILED"
    cleanup = {"state": "NOT_NEEDED"}
    output = log_path.open("xb")
    digest = hashlib.sha256()

    def event(kind, value):
        emit(kind, {"utc": datetime.now(timezone.utc).isoformat(), "elapsed_seconds": round(time.monotonic() - started, 3), **value})

    def consume():
        carry = b""
        try:
            while True:
                chunk = proc.stdout.read1(16384)
                if not chunk:
                    break
                with lock:
                    state["total_bytes"] += len(chunk)
                    state["tail"] = (state["tail"] + chunk)[-tail_bytes:]
                    matches = list(STATUS_RE.finditer(carry + chunk))
                    if matches:
                        values = matches[-1].groups()
                        state["last_status"] = {"completed": int(values[0]), "total": int(values[1]), "running": int(values[2]), "ninja_elapsed_seconds": float(values[3])}
                    carry = (carry + chunk)[-256:]
                    room = max_log_bytes - state["retained_bytes"]
                keep = chunk[:max(0, room)]
                # Only this reader owns output/digest. Never hold the controller's
                # state lock across potentially blocking local filesystem I/O.
                if keep:
                    output.write(keep)
                    output.flush()
                    digest.update(keep)
                with lock:
                    state["retained_bytes"] += len(keep)
                    if len(keep) != len(chunk):
                        state["failure"] = "LOG_LIMIT"
        except BaseException as exc:
            with lock:
                state["failure"] = "READER_ERROR_" + type(exc).__name__
        finally:
            try:
                output.close()
                proc.stdout.close()
            except Exception as exc:
                with lock:
                    state["failure"] = "READER_CLOSE_ERROR_" + type(exc).__name__
            finally:
                done.set()

    try:
        proc = subprocess.Popen([str(x) for x in args], **opts)
        reader = threading.Thread(target=consume, name="owned-build-output-reader", daemon=True)
        reader.start()
        reader_started = True
        event("BUILD_STARTED", {"timeout_seconds": timeout, "max_log_bytes": max_log_bytes})
        deadline = started + timeout
        next_sample = next_progress = started
        last_status = None
        parent_exited_at = None
        while True:
            now = time.monotonic()
            with lock:
                snap = dict(state)
            if snap["failure"]:
                outcome = snap["failure"]
                break
            if now >= deadline:
                outcome = "TIMED_OUT"
                break
            if now >= next_sample:
                try:
                    sample = sampler(proc)
                except Exception as exc:
                    sample = {"status": "UNAVAILABLE", "error_type": type(exc).__name__}
                event("BUILD_RESOURCE", sample)
                next_sample = now + sample_interval
            if now >= next_progress:
                status = snap["last_status"]
                if status is not None and status != last_status:
                    event("BUILD_PROGRESS", status)
                    last_status = status
                next_progress = now + progress_interval
            code = proc.poll()
            if code is not None:
                parent_exited_at = parent_exited_at or now
                if done.is_set():
                    outcome = "SUCCESS" if code == 0 else "CHILD_FAILED"
                    break
                if now - parent_exited_at >= 2:
                    outcome = "CAPTURE_EOF_UNCERTAIN"
                    break
            time.sleep(min(poll_interval, max(0, deadline - now)))
    except BaseException as exc:
        outcome = "CAPTURE_ERROR_" + type(exc).__name__
    finally:
        if proc is None:
            output.close()
        elif outcome != "SUCCESS":
            try:
                cleanup = terminate(proc, log_path.with_suffix(".termination.txt"))
            except Exception as exc:
                cleanup = {"state": "TERMINATION_CALLBACK_FAILED", "error_type": type(exc).__name__,
                           "descendant_shutdown": "NOT_INDEPENDENTLY_VERIFIED"}
                try:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=5)
                    cleanup["parent_reaped"] = True
                except Exception as fallback:
                    cleanup.update(parent_reaped=False, parent_reap_error=type(fallback).__name__)
        if reader_started:
            reader.join(timeout=5)
        elif proc is not None:
            output.close()
            proc.stdout.close()
        with lock:
            snap = dict(state)
        if reader_started and reader.is_alive():
            cleanup["reader_eof"] = "UNCONFIRMED"
            if outcome == "SUCCESS":
                outcome = "CAPTURE_EOF_UNCERTAIN"
        else:
            cleanup["reader_eof"] = "CONFIRMED" if reader_started else "NOT_STARTED"
        # A late reader error or size-cap hit can never become a successful log.
        if snap["failure"]:
            outcome = snap["failure"]
        result = {"state": outcome, "returncode": proc.poll() if proc is not None else None,
                  "total_bytes_seen": snap["total_bytes"], "retained_bytes": snap["retained_bytes"],
                  "log_sha256": digest.hexdigest() if done.is_set() else None,
                  "last_ninja_status": snap["last_status"], "cleanup": cleanup, "elapsed_seconds": round(time.monotonic() - started, 3)}
        event("BUILD_CAPTURE_RESULT", {k: v for k, v in result.items() if k != "cleanup"})
        if outcome != "SUCCESS":
            # Only the bounded tail is exposed. Full local logs never become artifacts.
            event("BUILD_TIMEOUT_OR_FAILURE_TAIL", {"text": safe_text(snap["tail"].decode("utf-8", errors="replace"), aliases), "max_bytes_before_decode": tail_bytes})
            event("BUILD_CHILD_CLEANUP", {k: safe_text(v, aliases) if isinstance(v, str) else v for k, v in cleanup.items()})
    return result
