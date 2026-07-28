"""Safe subprocess wrapper for CLI tools (nmap, gobuster, nikto, ...)."""
from __future__ import annotations
import shutil
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
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return ToolResult(command, proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as e:
        return ToolResult(command, -1, e.stdout or "", e.stderr or "", timed_out=True)
