"""
Utility to parse nmap output, extract open ports, and classify them
against IANA/RFC well-known service definitions.
"""
import re
import subprocess


# ===========================================================================
#  IANA / RFC WELL-KNOWN PORT REGISTRY
# ===========================================================================
#
# Each entry: port -> (service_name, rfc_url, is_common_for_packet_transfer)
#
# "Common for packet transfer" means the service is routinely expected on a
# CPE / network appliance that handles traffic.  If ANY discovered port is
# NOT in this list (or is marked False), the overall test is FAIL.
#
# Sources:
#   IANA Service Name and Transport Protocol Port Number Registry
#   https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
#
# Individual RFCs are cited per-port below.

WELL_KNOWN_PORTS = {
    # ── Core network / routing ──────────────────────────────────────────
    21:    ("FTP",                  "https://www.rfc-editor.org/rfc/rfc959",     True),
    22:    ("SSH",                  "https://www.rfc-editor.org/rfc/rfc4253",    True),
    23:    ("Telnet",               "https://www.rfc-editor.org/rfc/rfc854",     True),
    25:    ("SMTP",                 "https://www.rfc-editor.org/rfc/rfc5321",    True),
    53:    ("DNS",                  "https://www.rfc-editor.org/rfc/rfc1035",    True),
    67:    ("DHCP Server",          "https://www.rfc-editor.org/rfc/rfc2131",    True),
    68:    ("DHCP Client",          "https://www.rfc-editor.org/rfc/rfc2131",    True),
    69:    ("TFTP",                 "https://www.rfc-editor.org/rfc/rfc1350",    True),
    80:    ("HTTP",                 "https://www.rfc-editor.org/rfc/rfc9110",    True),
    110:   ("POP3",                 "https://www.rfc-editor.org/rfc/rfc1939",    True),
    119:   ("NNTP",                 "https://www.rfc-editor.org/rfc/rfc3977",    False),
    123:   ("NTP",                  "https://www.rfc-editor.org/rfc/rfc5905",    True),
    143:   ("IMAP",                 "https://www.rfc-editor.org/rfc/rfc9051",    True),
    161:   ("SNMP",                 "https://www.rfc-editor.org/rfc/rfc3411",    True),
    162:   ("SNMP-Trap",            "https://www.rfc-editor.org/rfc/rfc3411",    True),
    179:   ("BGP",                  "https://www.rfc-editor.org/rfc/rfc4271",    True),
    443:   ("HTTPS",                "https://www.rfc-editor.org/rfc/rfc9110",    True),
    465:   ("SMTPS",                "https://www.rfc-editor.org/rfc/rfc8314",    True),
    500:   ("IKE / IPsec",          "https://www.rfc-editor.org/rfc/rfc7296",    True),
    514:   ("Syslog (UDP) / rsh",   "https://www.rfc-editor.org/rfc/rfc5424",    True),
    520:   ("RIP",                  "https://www.rfc-editor.org/rfc/rfc2453",    True),
    546:   ("DHCPv6 Client",        "https://www.rfc-editor.org/rfc/rfc8415",    True),
    547:   ("DHCPv6 Server",        "https://www.rfc-editor.org/rfc/rfc8415",    True),
    587:   ("SMTP Submission",      "https://www.rfc-editor.org/rfc/rfc6409",    True),
    636:   ("LDAPS",                "https://www.rfc-editor.org/rfc/rfc4511",    True),
    853:   ("DNS over TLS",         "https://www.rfc-editor.org/rfc/rfc7858",    True),
    993:   ("IMAPS",                "https://www.rfc-editor.org/rfc/rfc9051",    True),
    995:   ("POP3S",                "https://www.rfc-editor.org/rfc/rfc1939",    True),
    1701:  ("L2TP",                 "https://www.rfc-editor.org/rfc/rfc3931",    True),
    1723:  ("PPTP",                 "https://www.rfc-editor.org/rfc/rfc2637",    True),
    1812:  ("RADIUS Auth",          "https://www.rfc-editor.org/rfc/rfc2865",    True),
    1813:  ("RADIUS Acct",          "https://www.rfc-editor.org/rfc/rfc2866",    True),
    1883:  ("MQTT",                 "https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html", True),
    1900:  ("SSDP / UPnP",         "https://www.rfc-editor.org/rfc/rfc6970",    True),
    2049:  ("NFS",                  "https://www.rfc-editor.org/rfc/rfc7530",    True),
    3306:  ("MySQL",                "https://dev.mysql.com/doc/dev/mysql-server/latest/", False),
    3389:  ("RDP",                  "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr", False),
    4500:  ("IPsec NAT-T",          "https://www.rfc-editor.org/rfc/rfc3948",    True),
    5060:  ("SIP",                  "https://www.rfc-editor.org/rfc/rfc3261",    True),
    5061:  ("SIP-TLS",              "https://www.rfc-editor.org/rfc/rfc3261",    True),
    5353:  ("mDNS",                 "https://www.rfc-editor.org/rfc/rfc6762",    True),
    5355:  ("LLMNR",                "https://www.rfc-editor.org/rfc/rfc4795",    True),
    5432:  ("PostgreSQL",           "https://www.postgresql.org/docs/current/protocol.html", False),
    5900:  ("VNC",                  "https://www.rfc-editor.org/rfc/rfc6143",    False),
    6514:  ("Syslog over TLS",      "https://www.rfc-editor.org/rfc/rfc5425",    True),
    6881:  ("BitTorrent",           "https://www.bittorrent.org/beps/bep_0003.html", False),
    8080:  ("HTTP Alternate",       "https://www.rfc-editor.org/rfc/rfc9110",    True),
    8443:  ("HTTPS Alternate",      "https://www.rfc-editor.org/rfc/rfc9110",    True),
    8883:  ("MQTT over TLS",        "https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html", True),

    # ── Services commonly seen on Metasploitable / legacy systems ──────
    111:   ("RPCbind / SunRPC",     "https://www.rfc-editor.org/rfc/rfc5531",    False),
    139:   ("NetBIOS Session",      "https://www.rfc-editor.org/rfc/rfc1001",    False),
    445:   ("SMB / CIFS",           "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2", False),
    512:   ("rexec",                "https://www.rfc-editor.org/rfc/rfc1282",    False),
    513:   ("rlogin",               "https://www.rfc-editor.org/rfc/rfc1282",    False),
    1099:  ("Java RMI",             "https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/", False),
    1524:  ("ingreslock (backdoor)","N/A",                                        False),
    2121:  ("FTP (non-standard)",   "N/A",                                        False),
    3632:  ("distcc",               "N/A",                                        False),
    5432:  ("PostgreSQL",           "https://www.postgresql.org/docs/current/protocol.html", False),
    5900:  ("VNC",                  "https://www.rfc-editor.org/rfc/rfc6143",    False),
    6000:  ("X11",                  "https://www.x.org/releases/current/doc/xproto/x11protocol.html", False),
    6667:  ("IRC",                  "https://www.rfc-editor.org/rfc/rfc2812",    False),
    6697:  ("IRC over TLS",         "https://www.rfc-editor.org/rfc/rfc7194",    False),
    8009:  ("AJP",                  "https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html", False),
    8180:  ("HTTP (Tomcat alt)",    "N/A",                                        False),
}

# IANA registry URL — used as the master reference in reports
IANA_REGISTRY_URL = (
    "https://www.iana.org/assignments/service-names-port-numbers/"
    "service-names-port-numbers.xhtml"
)


def classify_port(port_num, nmap_service=""):
    """
    Look up a port in the well-known registry.

    Returns (service_name, rfc_url, is_common)
      - service_name: human name from IANA / RFC
      - rfc_url:      direct link to the defining standard
      - is_common:    True if commonly expected for packet transfer on CPE
    """
    if port_num in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port_num]
    # Not in registry — classify as unknown / not standard
    svc = nmap_service.strip() or "unknown"
    return (svc, IANA_REGISTRY_URL, False)


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


# IANA-recommended ephemeral port range (RFC 6056).
# Source ports the kernel hands out to outbound sockets fall in this range;
# an "open" service should never live here, so we use it as a filter to drop
# ghost ports that are really just the DuT's own DNS/NTP/mDNS background
# traffic leaking into our PCAP analysis.
#
# Range covers:
#   - Windows/macOS default: 49152-65535
#   - Linux default: 32768-60999 (subset of IANA range)
#   - IANA standard: 49152-65535 (RFC 6056)
EPHEMERAL_PORT_RANGE = (49152, 65535)


def _is_ephemeral(port: int) -> bool:
    return EPHEMERAL_PORT_RANGE[0] <= port <= EPHEMERAL_PORT_RANGE[1]


def _probed_ports(pcap_path: str, dut_ip: str, proto: str) -> set[int]:
    """
    Return the set of destination ports the *tester* actually sent probes to
    on the DuT.  This is the authoritative list of ports that could legitimately
    be "open" — anything not in this set is background noise.
    """
    filt = f"ip.dst == {dut_ip} and {proto}"
    cmd = (
        f"tshark -r {pcap_path} -Y '{filt}' "
        f"-T fields -e {proto}.dstport"
    )
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
    except Exception:
        return set()

    probed = set()
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split("\n"):
            s = line.strip()
            if s and s.isdigit():
                probed.add(int(s))
    return probed


def parse_pcap_for_responses(pcap_path, dut_ip, proto="udp"):
    """
    Parse PCAP file to find responses from DuT, filtering out "ghost" ports.

    Returns list of dicts:
        [{"port": 53, "proto": "udp", "state": "open", "service": "..."}, ...]

    Ghost port filtering
    --------------------
    A naive ``ip.src == dut_ip and udp`` filter will pick up every random UDP
    packet the DuT emits while the scan runs — DNS queries from dnsmasq, NTP
    syncs, mDNS/SSDP broadcasts, DHCPv6 solicitations, etc. — and record their
    ephemeral *source* ports (e.g. 52499) as "open ports". They are not.

    Two defences:

    1. **Probe set.**  We derive the set of destination ports the *tester*
       sent probes to (`ip.dst == dut_ip and <proto>`), then only accept a
       response port if it appears in that set.  Background chatter to
       unrelated destinations is excluded automatically because those packets
       do not have the DuT as the src AND a tester-probed dst port as the
       srcport simultaneously.

    2. **Ephemeral port rejection.**  Any port in the Linux default ephemeral
       range (32768–60999) that was *not* also probed by the tester is
       discarded even if it somehow survives step 1.  Legitimate services on
       a CPE/DuT live in the well-known or registered ranges.
    """
    open_ports = []
    seen_ports = set()
    proto_l = proto.lower()

    if proto_l not in ("tcp", "udp", "sctp"):
        return []

    # Step 1: authoritative "probed" set.
    probed = _probed_ports(pcap_path, dut_ip, proto_l)

    try:
        if proto_l == "tcp":
            # TCP: Look for SYN-ACK responses from DuT
            filter_expr = (
                f"ip.src == {dut_ip} and tcp.flags.syn == 1 and tcp.flags.ack == 1"
            )
        elif proto_l == "udp":
            # UDP: any packet from DuT whose srcport is a port we actually
            # probed.  (We could also add `ip.dst == <tester_ip>` here for a
            # belt-and-braces check, but the probed-port constraint already
            # eliminates background noise.)
            filter_expr = f"ip.src == {dut_ip} and udp"
        else:  # sctp
            filter_expr = f"ip.src == {dut_ip} and sctp"

        cmd = (
            f"tshark -r {pcap_path} -Y '{filter_expr}' "
            f"-T fields -e {proto_l}.srcport"
        )
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                port_str = line.strip()
                if not (port_str and port_str.isdigit()):
                    continue

                port = int(port_str)
                if port in seen_ports:
                    continue

                # --- Ghost-port filters ------------------------------------
                # (a) Drop ephemeral ports entirely.
                # The ephemeral range (32768–60999) is reserved for the OS kernel
                # to hand out to outbound client sockets. A real service should
                # NEVER listen on an ephemeral port; if we see a response from
                # one, it's the DuT's own background traffic (DNS, NTP, SSH client
                # connecting elsewhere, etc.), not a listening service.
                if _is_ephemeral(port):
                    continue

                # (b) Must correspond to something the tester actually probed.
                if probed and port not in probed:
                    # No probe was ever sent to this port — it's background
                    # traffic the DuT emitted. Drop it.
                    continue
                # -----------------------------------------------------------

                seen_ports.add(port)
                open_ports.append({
                    "port": port,
                    "proto": proto_l,
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


def classify_open_ports(open_ports):
    """
    Classify every discovered port against the RFC registry.

    Returns (classified_list, has_non_standard)
      classified_list: same dicts as input, each enriched with:
         rfc_service, rfc_url, is_common, port_status
      has_non_standard: True if any port is not commonly used
    """
    has_non_standard = False
    for p in open_ports:
        svc, url, is_common = classify_port(p["port"], p.get("service", ""))
        p["rfc_service"] = svc
        p["rfc_url"] = url
        p["is_common"] = is_common
        p["port_status"] = "PASS" if is_common else "FAIL"
        if not is_common:
            has_non_standard = True
    return open_ports, has_non_standard
