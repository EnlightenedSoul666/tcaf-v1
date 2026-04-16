"""
Shared helpers for ICMP test cases (IPv4 and IPv6).
Unified Send Tests + Process (config change) compliance tests
per ETSI TS 133 117 V17.2.0 Section 4.2.4.1.1.2.

DuT = OpenWRT router for ALL tests.
Each test sends a purposeful packet and expects a specific response.
"""

from core.step_runner import StepRunner
from steps.pcap_start_step import PcapStartStep
from steps.pcap_stop_step import PcapStopStep
from steps.command_step import CommandStep
from steps.screenshot_step import ScreenshotStep
from steps.wireshark_packet_screenshot_step import WiresharkPacketScreenshotStep
from steps.analyze_pcap_step import AnalyzePcapStep
import re
import subprocess
import time


def _sh(cmd, timeout=10):
    """Run a shell command, return stdout on success or '' on any failure."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
#  Scapy address helper — strip %zone before passing to scapy
# ---------------------------------------------------------------------------

def _scapy_addr(addr):
    """
    Strip the %zone suffix from an IPv6 address before use in scapy.

    Scapy does not understand the zone-id syntax ('fe80::1%eth0').
    When it sees a '%' in the string it tries a DNS lookup, fails with
    'Name or service not known', and aborts the whole send command.

    Examples:
      'fdd4:48ab:15e6::1'   -> 'fdd4:48ab:15e6::1'  (unchanged)
      'fe80::1%eth0'        -> 'fe80::1'
    """
    if addr and '%' in addr:
        return addr.split('%')[0]
    return addr or ""


# ---------------------------------------------------------------------------
#  Route command helper (handles link-local %zone syntax)
# ---------------------------------------------------------------------------

def _ipv6_route_via_clause(ipv6_addr):
    """
    Convert an IPv6 address (possibly with %zone) into a 'via ... dev ...'
    clause suitable for `ip -6 route add`.

    Examples:
      'fdd4:48ab:15e6::1'      -> 'via fdd4:48ab:15e6::1'
      'fe80::1%eth0'           -> 'via fe80::1 dev eth0'
      'fe80::1%wlan0'          -> 'via fe80::1 dev wlan0'
    """
    if not ipv6_addr:
        return None
    if '%' not in ipv6_addr:
        return f"via {ipv6_addr}"
    # Split 'fe80::1%eth0' into address and interface
    addr, iface = ipv6_addr.split('%', 1)
    return f"via {addr} dev {iface}"


# ---------------------------------------------------------------------------
#  Traceroute hop extraction
# ---------------------------------------------------------------------------
#
# The Redirect and Process tests decide PASS/FAIL by comparing the hop path
# to the auxiliary machine before vs. after the stimulus.
#
# KEY INSIGHT: Hop *numbers* can change between BEFORE and AFTER if timeout
# lines (* * *) appear/disappear, even though the actual routing path is identical.
#
# Example:
#   BEFORE: 1 OpenWRT, 2 timeout, 3 Metasploitable
#   AFTER:  1 OpenWRT, 2 Metasploitable
#
# If we compare hop numbers, these look different (3 vs 2). But the actual
# path is the same: OpenWRT → Metasploitable.
#
# SOLUTION: Extract only the IP addresses in order (ignoring hop numbers
# and timeouts), and compare those. Identical IP sequence = PASS (DuT did
# not change routing). Different IP sequence = FAIL (DuT accepted redirect).
# ---------------------------------------------------------------------------

_HOP_RE = re.compile(r"^\s*(\d+)\s+([0-9a-fA-F:.]+)(?:\s|$)")


def _extract_hops(capture):
    """
    Extract the sequence of next-hop IP addresses from traceroute output,
    ignoring hop numbers and timeouts.

    Returns a list of IP strings in order, e.g. ['10.0.0.1', '192.168.1.100'].
    Skips timeout lines (hop marked as '*') and non-IP junk.

    This comparison is hop-number-agnostic: if line 2 times out in BEFORE
    but responds in AFTER, the extracted IP sequences still match.
    """
    if not capture:
        return []
    ips = []
    for line in capture.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        ip = m.group(2)
        # Skip '*' timeouts and obviously-not-an-IP tokens (e.g. hop number
        # followed by a word because of a failed DNS lookup with -n off).
        if ip == "*" or not any(c in ip for c in ".:"):
            continue
        ips.append(ip)
    return ips


# ===========================================================================
#  ROUTING SETUP / TEARDOWN
#  Route packets destined for auxiliary machine and the nonsense IP
#  through the OpenWRT router, so OpenWRT can generate ICMP errors
#  (Dest Unreachable, Time Exceeded, Redirect, etc.)
# ===========================================================================

def _run_traceroute(context, ip_version, targets, label):
    """
    Run traceroute to each target IP and take a screenshot.

    Args:
        ip_version: 4 or 6
        targets:    list of IP strings to trace
        label:      suffix for the screenshot (e.g. "before_routing" / "after_routing")
    """
    cmd_prefix = "traceroute -n -m 5 -w 2" if ip_version == 4 else "traceroute6 -n -m 5 -w 2"
    StepRunner([CommandStep("tester", "clear")]).run(context)
    header_cmd = f"echo -e '\\n=== TRACEROUTE {label.upper()} (IPv{ip_version}) ==='"
    StepRunner([CommandStep("tester", header_cmd)]).run(context)
    time.sleep(0.5)

    for target in targets:
        if not target:
            continue
        StepRunner([CommandStep("tester", f"{cmd_prefix} {target}")]).run(context)
        time.sleep(3)  # wait for traceroute to complete (max 5 hops x 2s = 10s worst case)

    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix=f"traceroute_ipv{ip_version}_{label}"
    )]).run(context)


def setup_routing(context, ip_version):
    """
    Configure the tester (Kali) routing table so that:
      - Packets to the nonsense IP go via OpenWRT  (for Dest Unreachable)
      - Packets to auxiliary machine go via OpenWRT  (for Redirect tests)

    Runs traceroute BEFORE and AFTER adding routes as evidence.
    This must run BEFORE the Send and Process tests.
    """
    sudo_pass = context.sudo_password or ""
    openwrt_ip = context.openwrt_ip
    openwrt_ipv6 = context.openwrt_ipv6

    if not openwrt_ip:
        print("[-] No OpenWRT IP provided. Cannot setup routing.")
        return

    # -- BEFORE: traceroute to document the current (default) path ----------
    if ip_version == 4:
        targets_before = [t for t in [context.nonsense_ip, context.auxiliary_ip] if t]
    else:
        targets_before = [t for t in [context.nonsense_ipv6, context.auxiliary_ipv6] if t]

    if targets_before:
        print(f"[*] Running traceroute BEFORE route setup (IPv{ip_version})")
        _run_traceroute(context, ip_version, targets_before, "before_routing")

    # -- Authenticate sudo once --------------------------------------------
    StepRunner([CommandStep("tester", f"echo '{sudo_pass}' | sudo -S true")]).run(context)
    time.sleep(1)

    # -- Add routes --------------------------------------------------------
    if ip_version == 4:
        nonsense_ip = context.nonsense_ip
        if nonsense_ip:
            cmd = f"sudo ip route add {nonsense_ip}/32 via {openwrt_ip}"
            print(f"[*] Adding route: {nonsense_ip} via {openwrt_ip}")
            StepRunner([CommandStep("tester", cmd)]).run(context)
            time.sleep(1)

        meta_ip = context.auxiliary_ip
        if meta_ip:
            cmd = f"sudo ip route add {meta_ip}/32 via {openwrt_ip}"
            print(f"[*] Adding route: {meta_ip} via {openwrt_ip}")
            StepRunner([CommandStep("tester", cmd)]).run(context)
            time.sleep(1)

    else:  # IPv6
        if not openwrt_ipv6:
            print("[-] No OpenWRT IPv6 address. Cannot setup IPv6 routing.")
            return

        via_clause = _ipv6_route_via_clause(openwrt_ipv6)
        if not via_clause:
            print("[-] Could not construct valid via clause for IPv6 route.")
            return

        nonsense_ipv6 = context.nonsense_ipv6
        if nonsense_ipv6:
            cmd = f"sudo ip -6 route add {nonsense_ipv6}/128 {via_clause}"
            print(f"[*] Adding IPv6 route: {nonsense_ipv6} {via_clause}")
            StepRunner([CommandStep("tester", cmd)]).run(context)
            time.sleep(1)

        meta_ipv6 = context.auxiliary_ipv6
        if meta_ipv6:
            cmd = f"sudo ip -6 route add {meta_ipv6}/128 {via_clause}"
            print(f"[*] Adding IPv6 route: {meta_ipv6} {via_clause}")
            StepRunner([CommandStep("tester", cmd)]).run(context)
            time.sleep(1)

    # -- Show routing table as evidence ------------------------------------
    StepRunner([CommandStep("tester", "clear")]).run(context)
    if ip_version == 4:
        StepRunner([CommandStep("tester", "ip route show")]).run(context)
    else:
        StepRunner([CommandStep("tester", "ip -6 route show")]).run(context)
    time.sleep(1)
    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix=f"routing_table_ipv{ip_version}"
    )]).run(context)

    # -- AFTER: traceroute to confirm traffic now flows through OpenWRT ----
    if targets_before:
        print(f"[*] Running traceroute AFTER route setup (IPv{ip_version})")
        _run_traceroute(context, ip_version, targets_before, "after_routing")


def teardown_routing(context, ip_version):
    """
    Remove the routes added by setup_routing().
    Runs AFTER all tests complete (cleanup).
    """
    sudo_pass = context.sudo_password or ""
    openwrt_ip = context.openwrt_ip
    openwrt_ipv6 = context.openwrt_ipv6

    if not openwrt_ip:
        return

    StepRunner([CommandStep("tester", f"echo '{sudo_pass}' | sudo -S true")]).run(context)
    time.sleep(1)

    if ip_version == 4:
        nonsense_ip = context.nonsense_ip
        if nonsense_ip:
            cmd = f"sudo ip route del {nonsense_ip}/32 via {openwrt_ip} 2>/dev/null"
            StepRunner([CommandStep("tester", cmd)]).run(context)

        meta_ip = context.auxiliary_ip
        if meta_ip:
            cmd = f"sudo ip route del {meta_ip}/32 via {openwrt_ip} 2>/dev/null"
            StepRunner([CommandStep("tester", cmd)]).run(context)

    else:
        if not openwrt_ipv6:
            return
        via_clause = _ipv6_route_via_clause(openwrt_ipv6)
        if not via_clause:
            return
        nonsense_ipv6 = context.nonsense_ipv6
        if nonsense_ipv6:
            cmd = f"sudo ip -6 route del {nonsense_ipv6}/128 {via_clause} 2>/dev/null"
            StepRunner([CommandStep("tester", cmd)]).run(context)

        meta_ipv6 = context.auxiliary_ipv6
        if meta_ipv6:
            cmd = f"sudo ip -6 route del {meta_ipv6}/128 {via_clause} 2>/dev/null"
            StepRunner([CommandStep("tester", cmd)]).run(context)

    # Flush any redirect cache entries
    if ip_version == 4:
        StepRunner([CommandStep("tester", "sudo ip route flush cache 2>/dev/null")]).run(context)
    else:
        StepRunner([CommandStep("tester", "sudo ip -6 route flush cache 2>/dev/null")]).run(context)

    print(f"[*] Routing cleanup complete (IPv{ip_version})")


# ===========================================================================
#  UNIFIED SEND TEST DEFINITIONS
#  Each test sends a purposeful packet and expects a specific response.
#  No more blind packet blasting via icmp_forge.py.
# ===========================================================================

def _get_ipv4_send_tests(context):
    """
    Define all IPv4 ICMP Send tests.
    Each test sends one specific packet and expects (or must NOT see)
    a specific response from the DuT (OpenWRT router).
    """
    dut_ip = context.dut_ip
    nonsense_ip = context.nonsense_ip or "192.168.99.99"
    aux_ip = context.auxiliary_ip
    # For TTL test, route through OpenWRT to a real target
    ttl_target = aux_ip if aux_ip else nonsense_ip

    tests = [
        {
            "name": "Echo Reply (Type 0)",
            "icmp_type": 0,
            "send_cmd": f"ping -c 3 -W 2 {dut_ip}",
            "response_filter": f"icmp.type == 0 and ip.src == {dut_ip}",
            "permitted": True,
            "wait_time": 5,
            "description": (
                f"ICMP Type 0 - Echo Reply: We ping the DuT (OpenWRT) at "
                f"{dut_ip}. The router responds with an Echo Reply, confirming "
                f"it is alive and reachable. Per ETSI TS 133 117, sending "
                f"Echo Reply is Optional for the DuT."
            ),
        },
        {
            "name": "Destination Unreachable (Type 3)",
            "icmp_type": 3,
            "send_cmd": f"ping -c 3 -W 2 {nonsense_ip}",
            "response_filter": f"icmp.type == 3 and ip.src == {dut_ip}",
            "permitted": True,
            "wait_time": 5,
            "description": (
                f"ICMP Type 3 - Destination Unreachable: We ping the "
                f"non-existent address {nonsense_ip}, routed through the DuT. "
                f"The router cannot deliver the packet and sends back a "
                f"Destination Unreachable message. Per ETSI, sending this "
                f"type is Permitted."
            ),
        },
        {
            "name": "Time Exceeded (Type 11)",
            "icmp_type": 11,
            "send_cmd": (
                f"sudo python3 -c \""
                f"from scapy.all import *; "
                f"send(IP(dst='{ttl_target}', ttl=1)/ICMP()/Raw(b'ITSAR-TTL-TEST'))"
                f"\""
            ),
            "response_filter": f"icmp.type == 11 and ip.src == {dut_ip}",
            "permitted": True,
            "wait_time": 4,
            "description": (
                f"ICMP Type 11 - Time Exceeded: We send a packet with TTL=1 "
                f"destined for {ttl_target} via the DuT. When the router tries "
                f"to forward it, TTL decrements to 0 and the packet is dropped. "
                f"The router informs us with a Time Exceeded message. Per ETSI, "
                f"sending this type is Optional."
            ),
        },
        {
            "name": "Parameter Problem (Type 12)",
            "icmp_type": 12,
            "send_cmd": (
                f"sudo python3 -c \""
                f"from scapy.all import *; "
                f"send(IP(dst='{dut_ip}', options=IPOption(b'\\x99\\x00\\x00\\x00'))/ICMP())"
                f"\""
            ),
            "response_filter": f"icmp.type == 12 and ip.src == {dut_ip}",
            "permitted": True,
            "wait_time": 4,
            "description": (
                f"ICMP Type 12 - Parameter Problem: We send a packet with "
                f"malformed IP header options to the DuT at {dut_ip}. The "
                f"router cannot parse the invalid options and reports the error "
                f"with a Parameter Problem message. Per ETSI, sending this "
                f"type is Permitted."
            ),
        },
        {
            "name": "Timestamp Reply (Type 14) - NOT PERMITTED",
            "icmp_type": 14,
            "send_cmd": (
                f"sudo python3 -c \""
                f"from scapy.all import *; "
                f"send(IP(dst='{dut_ip}')/ICMP(type=13))"
                f"\""
            ),
            "response_filter": f"icmp.type == 14 and ip.src == {dut_ip}",
            "permitted": False,
            "wait_time": 4,
            "description": (
                f"ICMP Type 14 - Timestamp Reply (NOT PERMITTED): We send a "
                f"Timestamp Request (Type 13) to the DuT at {dut_ip}. Per "
                f"ETSI TS 133 117, the DuT MUST NOT respond with a Timestamp "
                f"Reply. If no Type 14 response is seen, the DuT is compliant."
            ),
        },
    ]
    return tests


def _get_ipv6_send_tests(context):
    """
    Define all IPv6 ICMPv6 Send tests.
    Each test sends one specific packet and expects (or must NOT see)
    a specific response from the DuT (OpenWRT router).
    """
    dut_ipv6     = context.dut_ipv6
    openwrt_ipv6 = context.openwrt_ipv6 or dut_ipv6
    nonsense_ipv6 = context.nonsense_ipv6 or "fd00:dead:beef::99"
    aux_ipv6     = context.auxiliary_ipv6

    # Scapy does not accept %zone suffixes (e.g. 'fe80::1%eth0') — it tries
    # a DNS lookup and fails with 'Name or service not known'.  Strip them here
    # once so every send_cmd below gets a clean address automatically.
    s_dut      = _scapy_addr(dut_ipv6)
    s_aux      = _scapy_addr(aux_ipv6)
    s_nonsense = _scapy_addr(nonsense_ipv6)
    aux_ipv6 = context.auxiliary_ipv6
    # Scapy-safe hop-limit target
    s_hlim_target = s_aux if s_aux else s_nonsense

    tests = [
        {
            "name": "Echo Reply (Type 129)",
            "icmp_type": 129,
            "send_cmd": f"ping6 -c 3 -W 2 {dut_ipv6}",
            "response_filter": f"icmpv6.type == 129 and ipv6.src == {dut_ipv6}",
            "permitted": True,
            "wait_time": 5,
            "description": (
                f"ICMPv6 Type 129 - Echo Reply: We ping6 the DuT (OpenWRT) at "
                f"{dut_ipv6}. The router responds with an Echo Reply, confirming "
                f"IPv6 connectivity. Per ETSI TS 133 117, sending Echo Reply "
                f"is Optional."
            ),
        },
        {
            "name": "Time Exceeded (Type 3)",
            "icmp_type": 3,
            "send_cmd": (
                f"sudo python3 -c \""
                f"from scapy.all import *; "
                f"send(IPv6(dst='{s_hlim_target}', hlim=1)/ICMPv6EchoRequest())"
                f"\""
            ),
            "response_filter": f"icmpv6.type == 3 and ipv6.src == {dut_ipv6}",
            "permitted": True,
            "wait_time": 4,
            "description": (
                f"ICMPv6 Type 3 - Time Exceeded: We send a packet with "
                f"Hop Limit=1 destined for {hlim_target} via the DuT. The "
                f"router tries to forward it, decrements the hop limit to 0, "
                f"and sends back a Time Exceeded message. Per ETSI, sending "
                f"this type is Optional."
            ),
        },
        {
            "name": "Parameter Problem (Type 4)",
            "icmp_type": 4,
            "send_cmd": (
                f"sudo python3 -c \""
                f"from scapy.all import *; "
                f"send(IPv6(dst='{s_dut}', nh=255)/Raw(b'\\x00'*40))"
                f"\""
            ),
            "response_filter": f"icmpv6.type == 4 and ipv6.src == {dut_ipv6}",
            "permitted": True,
            "wait_time": 4,
            "description": (
                f"ICMPv6 Type 4 - Parameter Problem: We send a malformed "
                f"IPv6 packet with invalid Next Header (255) to the DuT at "
                f"{dut_ipv6}. The router cannot process the unknown header "
                f"and reports it with a Parameter Problem message. Per ETSI, "
                f"sending this type is Permitted."
            ),
        },
        {
            "name": "Router Advertisement (Type 134) - REQUIRED",
            "icmp_type": 134,
            # RFC 4861 s.6.2.6: a router MUST respond to a unicast RS.
            # We send two RS packets:
            #   1. Multicast to ff02::2 (all-routers) — standard host behaviour
            #   2. Unicast to dut_ipv6 — router MUST reply per RFC 4861
            # Sending both maximises the chance of an RA being observed.
            # Routers always source RAs from their link-local address.
            "send_cmd": (
                f"sudo python3 -c \""
                f"from scapy.all import *; "
                f"send(IPv6(dst='ff02::2')/ICMPv6ND_RS(), verbose=0); "
                f"import time; time.sleep(1); "
                f"send(IPv6(dst='{s_dut}')/ICMPv6ND_RS(), verbose=0)"
                f"\""
            ),
            # Routers source RA from their link-local address (RFC 4861 s.4.2),
            # so accept any icmpv6.type==134 regardless of source.
            "response_filter": "icmpv6.type == 134",
            "permitted": True,
            "wait_time": 8,
            "description": (
                f"ICMPv6 Type 134 - Router Advertisement (REQUIRED): "
                f"We send two Router Solicitation (Type 133) packets: "
                f"(1) multicast to ff02::2 (all-routers, standard host behaviour) "
                f"and (2) unicast directly to the DuT at {dut_ipv6} (RFC 4861 "
                f"s.6.2.6 states a router MUST respond to a unicast RS). "
                f"Sending both maximises the chance of capturing an RA. "
                f"Per RFC 4861 s.4.2, routers always source RAs from their "
                f"link-local address, so the filter accepts any icmpv6.type==134 "
                f"regardless of source. If a Type 134 is seen the DuT correctly "
                f"fulfils its role as an IPv6 router (PASS). INCONCLUSIVE means "
                f"neither stimulus produced an RA, which warrants further "
                f"investigation (rate-limiting, RA guard, accept_ra=0 on "
                f"forwarding interface)."
            ),
        },
        {
            "name": "Neighbour Advertisement (Type 136)",
            "icmp_type": 136,
            "send_cmd": (
                f"sudo python3 -c \""
                f"from scapy.all import *; "
                f"send(IPv6(dst='{s_dut}')/ICMPv6ND_NS(tgt='{s_dut}'))"
                f"\""
            ),
            "response_filter": f"icmpv6.type == 136 and ipv6.src == {dut_ipv6}",
            "permitted": True,
            "wait_time": 4,
            "description": (
                f"ICMPv6 Type 136 - Neighbour Advertisement: We send a "
                f"Neighbour Solicitation (Type 135) targeting the DuT address "
                f"{dut_ipv6}. The router responds with a Neighbour Advertisement "
                f"to confirm its presence at that address. Per ETSI, this is "
                f"part of normal NDP operation and is Permitted."
            ),
        },
    ]
    return tests


# ===========================================================================
#  UNIFIED SEND TEST EXECUTION
# ===========================================================================

def _echo_description(context, description):
    """Echo a test description in the tester terminal for screenshot capture."""
    StepRunner([CommandStep("tester", "echo ''")]).run(context)
    # Remove any single quotes to avoid bash issues
    safe = description.replace("'", "")
    StepRunner([CommandStep("tester", f"echo '{safe}'")]).run(context)


def run_unified_send_tests(context, ip_version):
    """
    Run unified ICMP Send tests for the given IP version.

    Flow:
    1. Authenticate sudo
    2. Start PCAP capture
    3. Send ALL test packets one by one (purposeful, not blind)
    4. Stop PCAP capture
    5. For each test: analyze PCAP, take screenshots, print description

    Returns (violations_list, pcap_status).
    """
    violations = []

    if ip_version == 4:
        tests = _get_ipv4_send_tests(context)
        label = "IPv4"
    else:
        tests = _get_ipv6_send_tests(context)
        label = "IPv6"

    # -- 1. Authenticate sudo -----------------------------------------------
    sudo_pass = context.sudo_password or ""
    StepRunner([CommandStep("tester", f"echo '{sudo_pass}' | sudo -S true")]).run(context)
    time.sleep(1)

    # -- 2. Start PCAP capture ----------------------------------------------
    pcap_filename = f"icmp_ipv{ip_version}_send.pcapng"
    iface = getattr(context, "tester_iface", None) or "eth0"
    StepRunner([PcapStartStep(interface=iface, filename=pcap_filename)]).run(context)
    time.sleep(1)

    # -- 3. Send ALL test packets -------------------------------------------
    print(f"\n[*] Sending {len(tests)} {label} test packets...")
    for test in tests:
        test_name = test["name"]
        StepRunner([CommandStep("tester", "clear")]).run(context)
        StepRunner([CommandStep("tester",
            f"echo '[*] Sending: {test_name}'"
        )]).run(context)
        print(f"    -> {test_name}")
        StepRunner([CommandStep("tester", test["send_cmd"])]).run(context)
        time.sleep(test["wait_time"])

    # -- 4. Wait for any remaining responses, then stop PCAP ----------------
    time.sleep(5)
    StepRunner([PcapStopStep()]).run(context)
    time.sleep(1)

    pcap_path = context.pcap_file

    # -- 5. Validate PCAP has packets ---------------------------------------
    pcap_status = validate_pcap(context, pcap_path)

    # -- 6. Analyze each test from the captured PCAP ------------------------
    print(f"\n[*] Analyzing {len(tests)} {label} test results...")
    for test in tests:
        test_violations = _analyze_single_test(context, test, pcap_path, ip_version)
        violations.extend(test_violations)

    return violations, pcap_status


def _analyze_single_test(context, test, pcap_path, ip_version):
    """
    Analyze a single ICMP test result from the captured PCAP.
    Shows tshark output + description in terminal, takes screenshots.

    Returns list of violations (empty for PASS, [icmp_type] for FAIL).
    """
    violations = []
    label = f"IPv{ip_version}"
    permitted_label = "PERMITTED" if test["permitted"] else "NOT PERMITTED"

    # -- 1. Clear and print header ------------------------------------------
    StepRunner([CommandStep("tester", "clear")]).run(context)
    header = f"=== {label} {test['name']} ({permitted_label}) ==="
    StepRunner([CommandStep("tester", f"echo ''")]).run(context)
    StepRunner([CommandStep("tester", f"echo '{header}'")]).run(context)
    StepRunner([CommandStep("tester", f"echo ''")]).run(context)

    # -- 2. Run tshark to display matching packets --------------------------
    tshark_cmd = f"tshark -r {pcap_path} -Y '{test['response_filter']}'"
    StepRunner([CommandStep("tester", tshark_cmd)]).run(context)
    time.sleep(2)

    # -- 3. Print description below the tshark output -----------------------
    _echo_description(context, test["description"])
    time.sleep(0.5)

    # -- 4. Take terminal screenshot ----------------------------------------
    suffix = f"send_ipv{ip_version}_type_{test['icmp_type']}"
    if not test["permitted"]:
        suffix = f"notpermitted_ipv{ip_version}_type_{test['icmp_type']}"
    StepRunner([ScreenshotStep(terminal="tester", suffix=suffix)]).run(context)

    # -- 5. Analyze PCAP for matching frames --------------------------------
    StepRunner([AnalyzePcapStep(filter_expr=test["response_filter"])]).run(context)
    found = context.matched_frame is not None

    # -- 6. Determine PASS / FAIL / INCONCLUSIVE ---------------------------
    if test["permitted"]:
        if found:
            status = "PASS"
            print(f"    [PASS] DuT sent {test['name']} as expected")
            StepRunner([WiresharkPacketScreenshotStep(
                suffix=suffix,
                display_filter=test["response_filter"]
            )]).run(context)
        else:
            status = "INCONCLUSIVE"
            print(f"    [?]   DuT did NOT send {test['name']} (optional / not observed)")
    else:
        if found:
            status = "FAIL"
            print(f"    [FAIL] VIOLATION: DuT sent {test['name']} which is NOT PERMITTED!")
            StepRunner([WiresharkPacketScreenshotStep(
                suffix=suffix,
                display_filter=test["response_filter"]
            )]).run(context)
            violations.append(test["icmp_type"])
        else:
            status = "PASS"
            print(f"    [PASS] DuT correctly did NOT send {test['name']}")

    # -- 7. Record sub-result for report ------------------------------------
    context.current_testcase.sub_results.append({
        "test_type": "Send",
        "icmp_type": test["icmp_type"],
        "icmp_name": test["name"],
        "ip_version": ip_version,
        "status": status,
        "category": "Permitted" if test["permitted"] else "Not Permitted",
        "description": test["description"],
    })

    return violations


# ===========================================================================
#  PROCESS TESTS (Configuration change verification)
#  Per ETSI: Certain ICMP types must NOT cause the DuT to change its
#  routing configuration. We verify by comparing routes before/after.
# ===========================================================================

def get_process_not_permitted_ipv4():
    """Process (config changes) = Not Permitted for IPv4."""
    return {
        5: "Redirect",
    }


def get_process_not_permitted_ipv6():
    """Process (config changes) = Not Permitted for IPv6."""
    return {
        137: "Redirect",
        133: "Router Solicitation",
        134: "Router Advertisement",
    }


def _test_redirect_real(context, ip_version, icmp_type, name, aux_ip, openwrt_ip, sudo_pass):
    """
    Test ICMP Redirect using real network conditions:
      1. Force route to auxiliary machine through OpenWRT
      2. Start PCAP capture
      3. Traceroute BEFORE (should show OpenWRT as intermediate hop)
      4. Ping auxiliary machine -- OpenWRT sees same-subnet destination
         and sends Redirect back to Kali
      5. Wait for Redirect to be processed
      6. Traceroute AFTER (should show direct route -- Redirect was sent)
      7. Stop PCAP, analyze for Redirect packet
      8. Clean up: remove forced route, flush redirect cache
    """
    openwrt_ipv6 = context.openwrt_ipv6 or openwrt_ip

    # -- 1. Force route through OpenWRT ------------------------------------
    StepRunner([CommandStep("tester", f"echo '{sudo_pass}' | sudo -S true")]).run(context)
    time.sleep(1)
    if ip_version == 4:
        route_cmd = f"sudo ip route replace {aux_ip}/32 via {openwrt_ip}"
    else:
        route_cmd = f"sudo ip -6 route replace {aux_ip}/128 via {openwrt_ipv6}"
    print(f"[*] Setting route: {aux_ip} via OpenWRT")
    StepRunner([CommandStep("tester", route_cmd)]).run(context)
    time.sleep(1)

    # -- 2. Start PCAP -----------------------------------------------------
    pcap_filename = f"icmp_ipv{ip_version}_redirect.pcapng"
    iface = getattr(context, "tester_iface", None) or "eth0"
    StepRunner([PcapStartStep(interface=iface, filename=pcap_filename)]).run(context)

    # -- 3. Traceroute BEFORE ----------------------------------------------
    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester",
        f"echo -e '\\n=== REDIRECT TEST: Type {icmp_type} ({name}) ==='"
    )]).run(context)
    StepRunner([CommandStep("tester", f"echo '--- BEFORE Redirect ---'")]).run(context)

    # Traceroute command + tee to a temp file so we can compare hop topology
    # using clean file content rather than the tmux pane buffer.
    # tmux capture-pane returns the full VISIBLE terminal buffer including
    # banner lines and per-hop RTTs that vary between runs -- comparing those
    # raw strings always yields "changed" even when the hop path is identical.
    # Writing output to a dedicated file (one per direction) avoids all that.
    tr_out_before = f"/tmp/tr{ip_version}_before_{icmp_type}.txt"
    tr_out_after  = f"/tmp/tr{ip_version}_after_{icmp_type}.txt"

    if ip_version == 4:
        tr_cmd_before = f"traceroute -n -m 5 -w 2 {aux_ip} | tee {tr_out_before}"
        tr_cmd_after  = f"traceroute -n -m 5 -w 2 {aux_ip} | tee {tr_out_after}"
    else:
        tr_cmd_before = f"traceroute6 -n -m 5 -w 2 {aux_ip} | tee {tr_out_before}"
        tr_cmd_after  = f"traceroute6 -n -m 5 -w 2 {aux_ip} | tee {tr_out_after}"

    StepRunner([CommandStep("tester", tr_cmd_before)]).run(context)
    # traceroute6 -m 5 -w 2 worst case: 5 hops × 2 s + 2 s margin = 12 s
    time.sleep(12)
    route_before = _sh(f"cat {tr_out_before}", timeout=5)
    print(f"    [i] route_before raw:\n{route_before}")
    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix=f"redirect_before_ipv{ip_version}_type_{icmp_type}"
    )]).run(context)

    # -- 4. Ping auxiliary machine to trigger Redirect from OpenWRT --------
    print(f"[*] Pinging {aux_ip} to trigger Redirect from OpenWRT...")
    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester", f"echo '--- Pinging to trigger Redirect ---'")]).run(context)
    if ip_version == 4:
        ping_cmd = f"ping -c 5 -W 2 {aux_ip}"
    else:
        ping_cmd = f"ping6 -c 5 -W 2 {aux_ip}"
    StepRunner([CommandStep("tester", ping_cmd)]).run(context)
    time.sleep(7)
    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix=f"redirect_ping_ipv{ip_version}_type_{icmp_type}"
    )]).run(context)

    # -- 5. Traceroute AFTER -----------------------------------------------
    print(f"[*] Traceroute AFTER Redirect...")
    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester", f"echo '--- AFTER Redirect ---'")]).run(context)
    StepRunner([CommandStep("tester", tr_cmd_after)]).run(context)
    time.sleep(12)
    route_after = _sh(f"cat {tr_out_after}", timeout=5)
    print(f"    [i] route_after raw:\n{route_after}")
    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix=f"redirect_after_ipv{ip_version}_type_{icmp_type}"
    )]).run(context)

    # -- 6. Stop PCAP ------------------------------------------------------
    StepRunner([PcapStopStep()]).run(context)

    # -- 7. Analyze PCAP for Redirect packet -------------------------------
    pcap_path = context.pcap_file
    if ip_version == 4:
        redirect_filter = f"icmp.type == 5 and ip.src == {openwrt_ip}"
    else:
        redirect_filter = f"icmpv6.type == 137 and ipv6.src == {openwrt_ipv6}"

    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester",
        f"echo '=== Checking PCAP for Redirect (Type {icmp_type}) ==='"
    )]).run(context)
    tshark_cmd = f"tshark -r {pcap_path} -Y '{redirect_filter}'"
    StepRunner([CommandStep("tester", tshark_cmd)]).run(context)
    time.sleep(2)

    # Print description for Redirect test
    redirect_desc = (
        f"ICMP Redirect Test: We force traffic to {aux_ip} through the DuT "
        f"(OpenWRT). When the router sees the packet entering and exiting "
        f"the same interface, it sends an ICMP Redirect telling us to send "
        f"directly to {aux_ip}. Per ETSI TS 133 117, the DuT MUST NOT "
        f"change its own routing configuration based on received Redirects."
    )
    _echo_description(context, redirect_desc)

    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix=f"redirect_pcap_ipv{ip_version}_type_{icmp_type}"
    )]).run(context)

    StepRunner([AnalyzePcapStep(filter_expr=redirect_filter)]).run(context)
    redirect_found = context.matched_frame is not None

    if redirect_found:
        print(f"[+] Redirect (Type {icmp_type}) captured in PCAP")
        StepRunner([WiresharkPacketScreenshotStep(
            suffix=f"redirect_packet_ipv{ip_version}_type_{icmp_type}",
            display_filter=redirect_filter
        )]).run(context)
    else:
        print(f"[-] No Redirect (Type {icmp_type}) found in PCAP")

    # -- 8. Clean up route and redirect cache ------------------------------
    if ip_version == 4:
        StepRunner([CommandStep("tester",
            f"sudo ip route del {aux_ip}/32 via {openwrt_ip} 2>/dev/null"
        )]).run(context)
        StepRunner([CommandStep("tester", "sudo ip route flush cache 2>/dev/null")]).run(context)
    else:
        StepRunner([CommandStep("tester",
            f"sudo ip -6 route del {aux_ip}/128 via {openwrt_ipv6} 2>/dev/null"
        )]).run(context)
        StepRunner([CommandStep("tester", "sudo ip -6 route flush cache 2>/dev/null")]).run(context)
    time.sleep(1)

    # -- 9. Determine result -----------------------------------------------
    # ETSI TS 133 117 compliance: the DuT/system MUST NOT change its routing
    # configuration based on received ICMP Redirects. We judge compliance by
    # comparing the traceroute BEFORE vs AFTER the Redirect was delivered.
    #
    #   hop topology unchanged -> Redirect was ignored  -> PASS (compliant)
    #   hop topology changed   -> Redirect was accepted -> FAIL (violation)
    #
    # We compare the *extracted hop lists*, not the raw terminal buffers.
    # See _extract_hops() for why: RTT jitter and different banner lines
    # make a string comparison of the raw buffers always inequal.
    #
    # Whether a Redirect packet was observed in the PCAP is recorded as
    # supporting evidence, but it is not the pass/fail criterion.
    hops_before = _extract_hops(route_before)
    hops_after  = _extract_hops(route_after)
    route_changed = hops_before != hops_after
    print(f"    [i] hops before: {hops_before}")
    print(f"    [i] hops after:  {hops_after}")

    if route_changed:
        print(f"[FAIL] Traceroute path CHANGED after Redirect (Type {icmp_type}) "
              f"-- DuT/system accepted the Redirect, violating ETSI TS 133 117")
        status = "FAIL"
    else:
        print(f"[PASS] Traceroute path UNCHANGED after Redirect (Type {icmp_type}) "
              f"-- DuT/system ignored the Redirect as required by ETSI TS 133 117")
        status = "PASS"

    if redirect_found:
        print(f"       (ICMP Redirect from OpenWRT was observed in the PCAP -- "
              f"confirms the stimulus reached the tester)")
    else:
        print(f"       (No ICMP Redirect observed in the PCAP -- OpenWRT did not "
              f"emit one for this traffic pattern)")

    return status


def _test_process_crafted(context, ip_version, icmp_type, name, aux_ip, openwrt_ip, sudo_pass):
    """
    Test Process = Not Permitted for non-Redirect types (RS, RA).
    Send a crafted ICMPv6 packet to the DuT and verify its routing
    does not change (traceroute before == traceroute after).
    """
    openwrt_ipv6 = context.openwrt_ipv6 or openwrt_ip
    s_openwrt    = _scapy_addr(openwrt_ipv6)   # strip %zone for scapy

    # Use tee to write traceroute output to temp files so hop-topology
    # comparison is done on clean file content, not the tmux pane buffer.
    tr_out_before = f"/tmp/proc{ip_version}_before_{icmp_type}.txt"
    tr_out_after  = f"/tmp/proc{ip_version}_after_{icmp_type}.txt"

    if ip_version == 4:
        traceroute_cmd_before = f"traceroute -n -m 5 -w 2 {aux_ip} | tee {tr_out_before}"
        traceroute_cmd_after  = f"traceroute -n -m 5 -w 2 {aux_ip} | tee {tr_out_after}"
    else:
        traceroute_cmd_before = f"traceroute6 -n -m 5 -w 2 {aux_ip} | tee {tr_out_before}"
        traceroute_cmd_after  = f"traceroute6 -n -m 5 -w 2 {aux_ip} | tee {tr_out_after}"

    # 1. Traceroute BEFORE
    print(f"[*] Traceroute BEFORE sending Type {icmp_type}")
    StepRunner([CommandStep("tester", f"echo '--- BEFORE Type {icmp_type} ---'")]).run(context)
    StepRunner([CommandStep("tester", traceroute_cmd_before)]).run(context)
    time.sleep(12)
    route_before = _sh(f"cat {tr_out_before}", timeout=5)
    print(f"    [i] route_before raw:\n{route_before}")
    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix=f"process_before_ipv{ip_version}_type_{icmp_type}"
    )]).run(context)

    # 2. Send crafted packet
    print(f"[*] Sending Type {icmp_type} ({name}) to DuT (OpenWRT)...")
    StepRunner([CommandStep("tester", f"echo '{sudo_pass}' | sudo -S true")]).run(context)
    time.sleep(1)

    if icmp_type == 133:
        send_cmd = (
            f"sudo python3 -c \""
            f"from scapy.all import *; "
            f"send(IPv6(dst='{s_openwrt}')/ICMPv6ND_RS())\""
        )
        desc = (
            f"ICMPv6 Process Test - Router Solicitation (Type 133): We send "
            f"a Router Solicitation to the DuT at {openwrt_ipv6}. Per ETSI "
            f"TS 133 117, the DuT MUST NOT change its routing configuration "
            f"in response. We verify by comparing routes before and after."
        )
    elif icmp_type == 134:
        send_cmd = (
            f"sudo python3 -c \""
            f"from scapy.all import *; "
            f"send(IPv6(dst='{s_openwrt}')/ICMPv6ND_RA())\""
        )
        desc = (
            f"ICMPv6 Process Test - Router Advertisement (Type 134): We send "
            f"a Router Advertisement to the DuT at {openwrt_ipv6}. Per ETSI "
            f"TS 133 117, the DuT MUST NOT change its routing configuration "
            f"in response. We verify by comparing routes before and after."
        )
    else:
        return "SKIPPED"

    StepRunner([CommandStep("tester", send_cmd)]).run(context)
    time.sleep(3)

    # 3. Traceroute AFTER
    print(f"[*] Traceroute AFTER sending Type {icmp_type}")
    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester", f"echo '--- AFTER Type {icmp_type} ---'")]).run(context)
    StepRunner([CommandStep("tester", traceroute_cmd_after)]).run(context)
    time.sleep(12)
    route_after = _sh(f"cat {tr_out_after}", timeout=5)
    print(f"    [i] route_after raw:\n{route_after}")

    # Print description
    _echo_description(context, desc)

    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix=f"process_after_ipv{ip_version}_type_{icmp_type}"
    )]).run(context)

    # 4. Compare extracted hop topology (ignores banner lines + RTT jitter).
    hops_before = _extract_hops(route_before)
    hops_after  = _extract_hops(route_after)
    print(f"    [i] hops before: {hops_before}")
    print(f"    [i] hops after:  {hops_after}")
    if hops_before == hops_after:
        print(f"[PASS] DuT config UNCHANGED after Type {icmp_type} ({name})")
        return "PASS"
    else:
        print(f"[FAIL] VIOLATION: DuT config CHANGED after Type {icmp_type} ({name})!")
        return "FAIL"


def check_not_permitted_process(context, ip_version, dut_ip):
    """
    Test Process = Not Permitted ICMP types per ETSI.

    - Redirect (Type 5 / 137): Real network test -- force route through
      OpenWRT, ping auxiliary machine, capture Redirect from OpenWRT.
    - RS/RA (Type 133/134): Send crafted packet, compare traceroute
      before/after to verify DuT does not change config.
    """
    violations = []
    openwrt_ip = context.openwrt_ip
    openwrt_pass = context.openwrt_password
    sudo_pass = context.sudo_password or ""

    if not openwrt_ip or not openwrt_pass:
        print("[-] DuT (OpenWRT) credentials not provided. Skipping Process tests.")
        return violations

    if ip_version == 4:
        process_types = get_process_not_permitted_ipv4()
        aux_ip = context.auxiliary_ip
    else:
        process_types = get_process_not_permitted_ipv6()
        aux_ip = context.auxiliary_ipv6

    if not aux_ip:
        print(f"[-] No auxiliary machine IPv{ip_version} address. Skipping Process tests.")
        return violations

    for icmp_type, name in process_types.items():
        StepRunner([CommandStep("tester", "clear")]).run(context)
        header_cmd = f"echo -e '\\n=== PROCESS NOT PERMITTED: Type {icmp_type} ({name}) ==='"
        StepRunner([CommandStep("tester", header_cmd)]).run(context)

        # Redirect types: use real network flow
        if (ip_version == 4 and icmp_type == 5) or (ip_version == 6 and icmp_type == 137):
            status = _test_redirect_real(
                context, ip_version, icmp_type, name, aux_ip, openwrt_ip, sudo_pass)
        else:
            # RS/RA: use crafted packet + traceroute comparison
            status = _test_process_crafted(
                context, ip_version, icmp_type, name, aux_ip, openwrt_ip, sudo_pass)

        if status == "FAIL":
            violations.append(icmp_type)

        # Build description for the report
        openwrt_label = context.openwrt_ipv6 or openwrt_ip
        if (ip_version == 4 and icmp_type == 5) or (ip_version == 6 and icmp_type == 137):
            proc_desc = (
                f"Process Test - ICMP Redirect (Type {icmp_type}): An ICMP Redirect "
                f"is a message a router sends to a host saying 'there is a better "
                f"first hop for this destination, please use it directly next time'. "
                f"If honoured, the receiving system installs a host-route in its "
                f"routing cache and subsequent packets bypass the original gateway. "
                f"To exercise this, traffic to the auxiliary machine at {aux_ip} is "
                f"first forced through the DuT (OpenWRT at {openwrt_ip}) using an "
                f"'ip route replace ... via <openwrt>' command. The BEFORE traceroute "
                f"confirms that packets are crossing OpenWRT. We then ping {aux_ip}: "
                f"OpenWRT notices the destination is reachable on the same interface "
                f"the packet arrived on and emits an ICMP Redirect. The AFTER "
                f"traceroute is the compliance evidence -- if the path to {aux_ip} "
                f"still traverses OpenWRT, the Redirect was ignored (PASS). If the "
                f"path has collapsed to a direct hop, the Redirect was accepted and "
                f"the system is non-compliant (FAIL). Per ETSI TS 133 117 clause "
                f"1.10.2, the DuT MUST NOT alter its routing table based on received "
                f"ICMP Redirects. The captured PCAP + Wireshark frame document that "
                f"the stimulus actually reached the tester."
            )
        elif icmp_type == 133:
            proc_desc = (
                f"Process Test - Router Solicitation (Type 133, ICMPv6): A Router "
                f"Solicitation (RS) is the message a host sends on boot (to the "
                f"all-routers multicast address ff02::2) asking any on-link router "
                f"to immediately respond with a Router Advertisement. RS messages "
                f"themselves do not carry routes, but they invite routers to "
                f"advertise prefixes, default gateways, and configuration flags "
                f"that a receiver might then install. Per RFC 4861 a router should "
                f"only answer an RS -- it should never treat an RS as a reason to "
                f"change its OWN tables. For this test a crafted ICMPv6 RS is sent "
                f"to the DuT at {openwrt_label} with scapy "
                f"(IPv6(dst=DuT)/ICMPv6ND_RS()). A traceroute6 to {aux_ip} is "
                f"captured BEFORE the RS and AFTER the RS. The two screenshots are "
                f"compared byte-for-byte: identical output means the DuT's routing "
                f"table did not shift in response to the solicitation (PASS). Any "
                f"change in hop count, next-hop address, or latency would indicate "
                f"the DuT reconfigured itself on receipt of an RS (FAIL). Per ETSI "
                f"TS 133 117 clause 1.10.2 the DuT MUST NOT process incoming Router "
                f"Solicitations in a way that alters its routing configuration."
            )
        elif icmp_type == 134:
            proc_desc = (
                f"Process Test - Router Advertisement (Type 134, ICMPv6): A Router "
                f"Advertisement (RA) is the message a router sends (periodically or "
                f"in reply to an RS) carrying on-link prefixes, a default router "
                f"lifetime, MTU, and 'managed/other config' flags. On a host these "
                f"are the PRIMARY way a default gateway and IPv6 prefix get "
                f"installed (SLAAC) -- accepting a rogue RA is the classic "
                f"'rogue-RA' attack and can silently hijack a whole subnet. A router "
                f"DuT must therefore drop RAs arriving from non-trusted peers and "
                f"never rewrite its own tables from them (Linux enforces this with "
                f"net.ipv6.conf.*.accept_ra=0 on forwarding interfaces). For this "
                f"test a crafted ICMPv6 RA is sent to the DuT at {openwrt_label} "
                f"with scapy (IPv6(dst=DuT)/ICMPv6ND_RA()). A traceroute6 to "
                f"{aux_ip} is captured BEFORE and AFTER the RA. The compliance "
                f"check is a direct string comparison of the two traceroute outputs: "
                f"identical = DuT ignored the RA (PASS); different next-hop, hop "
                f"count or gateway = DuT accepted the RA and reconfigured (FAIL). "
                f"Per ETSI TS 133 117 clause 1.10.2 the DuT MUST NOT process "
                f"incoming Router Advertisements in a way that alters its routing "
                f"configuration."
            )
        else:
            proc_desc = ""

        context.current_testcase.sub_results.append({
            "test_type": "Process",
            "icmp_type": icmp_type,
            "icmp_name": name,
            "ip_version": ip_version,
            "status": status,
            "category": "Not Permitted",
            "description": proc_desc,
        })

    return violations


# ===========================================================================
#  PCAP VALIDATION
# ===========================================================================

def validate_pcap(context, pcap_path):
    """
    Check if PCAP captured any packets.
    Returns 'PASS' or 'INCONCLUSIVE'.
    """
    check_cmd = f"tshark -r {pcap_path} | wc -l"
    StepRunner([CommandStep("tester", check_cmd)]).run(context)
    time.sleep(1)
    output = context.terminal_manager.capture_output("tester")

    try:
        pkt_count = int(output.strip().split('\n')[-1].strip())
    except (ValueError, IndexError):
        pkt_count = -1

    if pkt_count == 0:
        print("[!] WARNING: 0 packets captured! ICMP packets may not have been sent.")
        print("[!] Ensure sudo works without password prompt in tmux.")
        return "INCONCLUSIVE"

    return "PASS"


# ===========================================================================
#  DEDICATED DESTINATION UNREACHABLE TEST (ICMPv6 Type 1)
#
#  Per RFC 4443 Section 3.1, a router generates ICMPv6 Type 1 when:
#    Code 0: No route to destination
#    Code 1: Communication administratively prohibited (firewall)
#    Code 2: Beyond scope of source address
#    Code 3: Address unreachable (NDP failed to resolve neighbour)
#    Code 4: Port unreachable
#
#  We target Code 3 (Address Unreachable): a random ULA address is placed in
#  OpenWRT's own LAN prefix. OpenWRT has a route for the prefix (it owns it),
#  so it will attempt NDP for the specific host. Nobody responds → Code 3.
#
#  To guarantee reliability we:
#   1. SSH to OpenWRT and flush the NDP cache for the nonsense address so
#      OpenWRT always starts a fresh NDP probe (avoids stale REACHABLE cache).
#   2. Verify the tester's route to nonsense_ipv6 is via OpenWRT.
#   3. Use scapy to send a burst of raw ICMPv6 Echo Requests (faster and more
#      controllable than ping6) across the full NDP timeout window.
# ===========================================================================

def run_dest_unreachable_test_ipv6(context):
    """
    Dedicated Destination Unreachable (Type 1 Code 3) test for IPv6.

    Workflow:
      1. SSH to OpenWRT and flush NDP cache for nonsense_ipv6
      2. Verify tester route to nonsense_ipv6 goes via OpenWRT
      3. Start PCAP capture
      4. Burst-send ICMPv6 Echo Requests to nonsense_ipv6 via scapy
      5. Stop PCAP and analyze for Type 1 from DuT
      6. Return PASS (Type 1 found) or INCONCLUSIVE (not found)
    """
    dut_ipv6  = context.dut_ipv6
    nonsense  = context.nonsense_ipv6

    if not (dut_ipv6 and nonsense):
        print("[-] Missing DuT or nonsense IPv6. Skipping Dest Unreachable test.")
        return "SKIPPED"

    if not context.openwrt_ip or not context.openwrt_password:
        print("[-] OpenWRT credentials required. Skipping Dest Unreachable test.")
        return "SKIPPED"

    print("\n" + "="*70)
    print("Dedicated Destination Unreachable Test (ICMPv6 Type 1 Code 3)")
    print("="*70)

    openwrt_ipv6 = context.openwrt_ipv6 or dut_ipv6
    via_clause   = _ipv6_route_via_clause(openwrt_ipv6)
    s_nonsense   = _scapy_addr(nonsense)   # strip %zone for scapy

    # -- 1. Flush OpenWRT NDP cache for nonsense address -------------------
    print(f"[1/5] Flushing OpenWRT NDP cache for {nonsense}...")
    flush_cmd = (
        f"sshpass -p '{context.openwrt_password}' "
        f"ssh -o StrictHostKeyChecking=no root@{context.openwrt_ip} "
        f"'ip -6 neigh del {nonsense} dev br-lan 2>/dev/null; "
        f" ip -6 neigh flush dev br-lan nud stale 2>/dev/null; "
        f" echo done'"
    )
    try:
        result = subprocess.run(flush_cmd, shell=True, capture_output=True, text=True, timeout=10)
        print(f"    OpenWRT NDP flush: {'OK' if 'done' in result.stdout else 'attempted'}")
    except Exception as e:
        print(f"    [!] NDP flush error: {e} (continuing)")

    # -- 2. Verify tester route is via OpenWRT ----------------------------
    print(f"[2/5] Verifying tester route to {nonsense}...")
    route_check = _sh(f"ip -6 route get {nonsense}", timeout=5)
    if openwrt_ipv6.split('%')[0] in route_check or "via" in route_check:
        print(f"    Route OK: {route_check.strip()}")
    else:
        print(f"    [!] Route may be missing. Adding now...")
        _sh(f"sudo ip -6 route add {nonsense}/128 {via_clause} 2>/dev/null")
        time.sleep(1)

    # -- 3. Start PCAP capture --------------------------------------------
    print("[3/5] Starting PCAP capture...")
    iface = getattr(context, "tester_iface", None) or "eth0"
    pcap_filename = "icmp_ipv6_dest_unreachable.pcapng"
    StepRunner([PcapStartStep(interface=iface, filename=pcap_filename)]).run(context)
    time.sleep(1)

    # -- 4. Burst-send Echo Requests to nonsense address -------------------
    # Send a burst over ~12 seconds so OpenWRT's NDP probe cycle
    # (3 probes × ~1s retransmit = ~3–5s total) completes within the window.
    print(f"[4/5] Sending ICMPv6 Echo Requests to {nonsense}...")
    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester",
        f"echo '[*] Sending burst to {nonsense} — expect Type 1 Code 3...'")]).run(context)

    # Use scapy burst: send 10 Echo Requests spread across 12 s
    send_cmd = (
        f"sudo python3 -c \""
        f"from scapy.all import *; import time; "
        f"pkt = IPv6(dst='{s_nonsense}')/ICMPv6EchoRequest(); "
        f"[send(pkt, verbose=0) or time.sleep(1.2) for _ in range(10)]\""
    )
    StepRunner([CommandStep("tester", send_cmd)]).run(context)
    time.sleep(14)   # Full NDP timeout + buffer

    # -- 5. Stop PCAP and analyze -----------------------------------------
    print("[5/5] Stopping PCAP and analyzing for Type 1...")
    StepRunner([PcapStopStep()]).run(context)
    time.sleep(1)

    pcap_path = context.pcap_file

    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester",
        f"echo '=== Type 1 (Dest Unreachable) Packets ===' && "
        f"tshark -r {pcap_path} -Y 'icmpv6.type == 1'")]).run(context)
    time.sleep(2)
    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix="dest_unreachable_dedicated"
    )]).run(context)

    du_filter = f"icmpv6.type == 1 and ipv6.src == {dut_ipv6}"
    StepRunner([AnalyzePcapStep(filter_expr=du_filter)]).run(context)
    du_found = context.matched_frame is not None

    if du_found:
        print("[+] Type 1 (Destination Unreachable) found")
        StepRunner([WiresharkPacketScreenshotStep(
            suffix="dest_unreachable_packet",
            display_filter=du_filter
        )]).run(context)
        status = "PASS"
    else:
        print("[-] No Type 1 found — check OpenWRT firewall/NDP settings")
        status = "INCONCLUSIVE"

    print("\n" + "="*70)
    print(f"Result: {status}")
    print(f"Target: {nonsense}")
    print(f"Expected: ICMPv6 Type 1 Code 3 (Address Unreachable) from {dut_ipv6}")
    print("="*70 + "\n")

    return status


# ===========================================================================
#  DEDICATED PACKET TOO BIG TEST (ICMPv6 Type 2)
#  Per RFC 8200 Section 4.2: PTB generated when packet > egress MTU
# ===========================================================================

def run_ptb_test_ipv6(context):
    """
    Dedicated Packet Too Big (Type 2) test for IPv6.

    Workflow:
      1. Query OpenWRT's current br-lan MTU via SSH
      2. Reduce to 1280 (packet will be 1400, triggering PTB)
      3. Start PCAP capture
      4. Send 1400-byte ICMPv6 Echo Request to auxiliary machine
      5. Stop PCAP and analyze for Type 2 from DuT
      6. Restore original MTU
      7. Return PASS (Type 2 found) or INCONCLUSIVE (not found)

    Returns status string: "PASS", "INCONCLUSIVE", or "SKIPPED"
    """
    dut_ipv6 = context.dut_ipv6
    aux_ipv6 = context.auxiliary_ipv6

    if not (dut_ipv6 and aux_ipv6):
        print("[-] Missing DuT or auxiliary IPv6. Skipping dedicated PTB test.")
        return "SKIPPED"

    if not context.openwrt_ip or not context.openwrt_password:
        print("[-] OpenWRT credentials required for PTB test. Skipping.")
        return "SKIPPED"

    original_mtu = None
    reduced_mtu  = 1280
    packet_size  = 1400
    s_aux        = _scapy_addr(aux_ipv6)   # strip %zone for scapy

    print("\n" + "="*70)
    print("Dedicated PTB Test (ICMPv6 Type 2)")
    print("="*70)

    # -- Query original MTU -----------------------------------------------
    print("[1/6] Querying OpenWRT br-lan MTU...")
    query_mtu_cmd = (
        f"sshpass -p '{context.openwrt_password}' "
        f"ssh -o StrictHostKeyChecking=no root@{context.openwrt_ip} "
        f"'ip link show br-lan 2>/dev/null | grep mtu | awk {{print $5}}' 2>/dev/null"
    )
    try:
        result = subprocess.run(query_mtu_cmd, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            mtu_str = result.stdout.strip()
            if mtu_str.startswith("mtu"):
                original_mtu = int(mtu_str.split()[1])
                print(f"    Original MTU: {original_mtu}")
    except Exception as e:
        print(f"    [!] Could not query MTU: {e}")

    # -- Reduce MTU -------------------------------------------------------
    print(f"[2/6] Reducing br-lan MTU to {reduced_mtu}...")
    reduce_mtu_cmd = (
        f"sshpass -p '{context.openwrt_password}' "
        f"ssh -o StrictHostKeyChecking=no root@{context.openwrt_ip} "
        f"'ip link set br-lan mtu {reduced_mtu}' 2>/dev/null"
    )
    try:
        result = subprocess.run(reduce_mtu_cmd, shell=True, capture_output=True, timeout=10)
        if result.returncode == 0:
            print(f"    ✓ MTU set to {reduced_mtu}")
    except Exception as e:
        print(f"    [!] Failed to reduce MTU: {e}")
    time.sleep(2)

    # -- Start PCAP capture -----------------------------------------------
    print("[3/6] Starting PCAP capture...")
    iface = getattr(context, "tester_iface", None) or "eth0"
    pcap_filename = "icmp_ipv6_ptb_dedicated.pcapng"
    StepRunner([PcapStartStep(interface=iface, filename=pcap_filename)]).run(context)
    time.sleep(2)

    # -- Send oversized packet --------------------------------------------
    print(f"[4/6] Sending {packet_size}-byte ICMPv6 Echo Request to {aux_ipv6}...")
    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester",
        f"echo '[*] Sending {packet_size}-byte packet to {aux_ipv6}...'")]).run(context)

    send_cmd = (
        f"sudo python3 -c \""
        f"from scapy.all import *; "
        f"send(IPv6(dst='{s_aux}')/ICMPv6EchoRequest()/Raw(b'A'*{packet_size}), verbose=0)\""
    )
    StepRunner([CommandStep("tester", send_cmd)]).run(context)
    time.sleep(5)

    # -- Stop PCAP and analyze --------------------------------------------
    print("[5/6] Stopping PCAP and analyzing...")
    StepRunner([PcapStopStep()]).run(context)
    time.sleep(1)

    pcap_path = context.pcap_file

    # Display PCAP analysis
    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester",
        f"echo '=== Type 2 (PTB) Packets ===' && "
        f"tshark -r {pcap_path} -Y 'icmpv6.type == 2'")]).run(context)
    time.sleep(2)
    StepRunner([ScreenshotStep(
        terminal="tester",
        suffix="ptb_dedicated_analysis"
    )]).run(context)

    # Check for Type 2 in PCAP
    ptb_filter = f"icmpv6.type == 2 and ipv6.src == {dut_ipv6}"
    StepRunner([AnalyzePcapStep(filter_expr=ptb_filter)]).run(context)
    ptb_found = context.matched_frame is not None

    if ptb_found:
        print("[+] Type 2 (PTB) packet found")
        StepRunner([WiresharkPacketScreenshotStep(
            suffix="ptb_dedicated_packet",
            display_filter=ptb_filter
        )]).run(context)
        ptb_status = "PASS"
    else:
        print("[-] No Type 2 packet found")
        ptb_status = "INCONCLUSIVE"

    # -- Restore original MTU ---------------------------------------------
    print(f"[6/6] Restoring original MTU...")
    if original_mtu:
        restore_mtu_cmd = (
            f"sshpass -p '{context.openwrt_password}' "
            f"ssh -o StrictHostKeyChecking=no root@{context.openwrt_ip} "
            f"'ip link set br-lan mtu {original_mtu}' 2>/dev/null"
        )
        try:
            result = subprocess.run(restore_mtu_cmd, shell=True, capture_output=True, timeout=10)
            if result.returncode == 0:
                print(f"    ✓ MTU restored to {original_mtu}")
        except Exception as e:
            print(f"    [!] Failed to restore MTU: {e}")
    time.sleep(1)

    # Summary
    print("\n" + "="*70)
    print(f"Result: {ptb_status}")
    print("="*70)
    print(f"Packet size: {packet_size} bytes")
    print(f"Reduced MTU: {reduced_mtu} bytes")
    print(f"Type 2 found: {'Yes' if ptb_found else 'No'}")
    print("="*70 + "\n")

    return ptb_status
