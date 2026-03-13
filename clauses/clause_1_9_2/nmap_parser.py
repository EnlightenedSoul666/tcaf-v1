"""
Utility to parse nmap output and extract open ports from both nmap output and PCAP files.
"""
import re
import subprocess


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


def parse_pcap_for_responses(pcap_path, dut_ip, proto="udp"):
    """
    Parse PCAP file to find responses from DuT.
    Returns list of dicts: [{"port": 53, "proto": "udp", "state": "open", "service": "unknown"}, ...]

    For UDP/SCTP: Look for any response from DuT on a given port.
    For TCP: Look for SYN-ACK responses.
    """
    open_ports = []
    seen_ports = set()

    try:
        if proto.lower() == "tcp":
            # TCP: Look for SYN-ACK responses from DuT
            filter_expr = f"ip.src == {dut_ip} and tcp.flags.syn == 1 and tcp.flags.ack == 1"
        elif proto.lower() == "udp":
            # UDP: Look for any response from DuT
            filter_expr = f"ip.src == {dut_ip} and udp"
        elif proto.lower() == "sctp":
            # SCTP: Look for INIT-ACK responses from DuT
            filter_expr = f"ip.src == {dut_ip} and sctp"
        else:
            return []

        # Run tshark to extract source ports from responses
        cmd = f"tshark -r {pcap_path} -Y '{filter_expr}' -T fields -e {proto}.srcport"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                port_str = line.strip()
                if port_str and port_str.isdigit():
                    port = int(port_str)
                    if port not in seen_ports:
                        seen_ports.add(port)
                        open_ports.append({
                            "port": port,
                            "proto": proto.lower(),
                            "state": "open",
                            "service": "unknown (from PCAP)",
                        })
    except Exception as e:
        print(f"[!] Error parsing PCAP: {e}")

    return open_ports


def merge_port_lists(nmap_ports, pcap_ports):
    """
    Merge nmap output and PCAP-derived ports, removing duplicates.
    Prefer nmap's service name when available.
    """
    merged = {p["port"]: p for p in nmap_ports}

    for pcap_port in pcap_ports:
        port_num = pcap_port["port"]
        if port_num not in merged:
            merged[port_num] = pcap_port

    return list(merged.values())
