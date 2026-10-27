"""Process CPU and resident memory snapshots without additional dependencies."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import os
import time


def snapshot() -> dict[str, float | int | None]:
    """RAM is sampled at boundaries; peak is process-wide, not per-case."""
    result = {"cpu_seconds": time.process_time(), "rss_bytes": None, "process_peak_rss_bytes": None}
    if os.name == "nt":
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [(name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = (wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
        counter = Counters()
        counter.cb = ctypes.sizeof(counter)
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counter), counter.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        result.update(rss_bytes=counter.WorkingSetSize, process_peak_rss_bytes=counter.PeakWorkingSetSize)
    elif os.path.isfile("/proc/self/statm"):
        with open("/proc/self/statm", encoding="ascii") as stream:
            result["rss_bytes"] = int(stream.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    return result
