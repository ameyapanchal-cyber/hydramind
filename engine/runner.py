"""Safe subprocess wrapper for CLI tools (nmap, gobuster, nikto, ...)."""
from __future__ import annotations
import os
import shutil
import signal
import subprocess
from dataclasses import dataclass


@dataclass
class ToolResult:
    command: list
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_tool(command: list, timeout: int = 300) -> ToolResult:
    binary = command[0]
    if not tool_available(binary):
        raise FileNotFoundError(
            f"'{binary}' is not installed. On Kali: sudo apt install {binary}"
        )
    proc = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
        return ToolResult(command, proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
        return ToolResult(command, -1, out or "", err or "", timed_out=True)
