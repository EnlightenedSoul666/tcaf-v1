"""
Utility to parse nmap output and extract open ports.
"""
import re


def parse_open_ports(nmap_output):
    """
    Parse nmap text output and return a list of dicts:
      [{"port": 22, "proto": "tcp", "state": "open", "service": "ssh"}, ...]
    """
    open_ports = []
    for line in nmap_output.strip().split("\n"):
        # Match lines like: 22/tcp   open  ssh
        match = re.match(r"^\s*(\d+)/(tcp|udp|sctp)\s+(open|open\|filtered)\s+(.*)", line)
        if match:
            open_ports.append({
                "port": int(match.group(1)),
                "proto": match.group(2),
                "state": match.group(3),
                "service": match.group(4).strip(),
            })
    return open_ports
