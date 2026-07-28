"""nmap module — run nmap and parse its XML into structured findings."""
from __future__ import annotations
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from engine.runner import run_tool, ToolResult


def run_nmap(target: str, extra_args=None, timeout: int = 300):
    xml_path = Path(tempfile.gettempdir()) / f"nmap_{target.replace('/', '_')}.xml"
    cmd = ["nmap", "-sV", "-T4", "-oX", str(xml_path), target]
    if extra_args:
        cmd[1:1] = extra_args
    result = run_tool(cmd, timeout=timeout)
    return result, str(xml_path)


def parse_nmap(xml_path: str):
    findings = []
    tree = ET.parse(xml_path)
    for host in tree.getroot().findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            findings.append({
                "host": addr,
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": svc.get("name") if svc is not None else "unknown",
                "product": svc.get("product") if svc is not None else "",
                "version": svc.get("version") if svc is not None else "",
            })
    return findings
