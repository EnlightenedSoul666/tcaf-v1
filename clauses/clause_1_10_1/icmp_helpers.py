"""
Shared helpers for ICMP test cases (IPv4 and IPv6).
Covers both "Respond to" and "Send" compliance tests per ITSAR table.
"""

from core.step_runner import StepRunner
from steps.pcap_start_step import PcapStartStep
from steps.pcap_stop_step import PcapStopStep
from steps.command_step import CommandStep
from steps.screenshot_step import ScreenshotStep
from steps.wireshark_packet_screenshot_step import WiresharkPacketScreenshotStep
from steps.analyze_pcap_step import AnalyzePcapStep
import time


# ---------------------------------------------------------------------------
#  RESPOND-TO TESTS (We send ICMP to DuT, check if it responds correctly)
# ---------------------------------------------------------------------------

def run_capture_cycle(context, forge_flag, target_ip, pcap_filename, log_file):
    """
    Start PCAP, authenticate sudo, run icmp_forge.py, wait, stop PCAP.
    Uses sudo password from CLI prompt (no 3-second tmux wait).
    """
    # 1. Start PCAP
    StepRunner([PcapStartStep(interface="eth0", filename=pcap_filename)]).run(context)

    # 2. Authenticate sudo using password from CLI prompt
    sudo_pass = context.sudo_password or ""
    StepRunner([CommandStep("tester", f"echo '{sudo_pass}' | sudo -S true")]).run(context)
    time.sleep(1)

    # 3. Fire the ICMP payload
    cmd = f"sudo python3 clauses/clause_1_10_1/icmp_forge.py --logfile {log_file} {forge_flag} {target_ip}"
    StepRunner([CommandStep("tester", "clear")]).run(context)
    StepRunner([CommandStep("tester", cmd)]).run(context)

    # 4. Wait for icmp_forge.py to finish sending all packets
    time.sleep(15)

    # 5. Stop PCAP
    StepRunner([PcapStopStep()]).run(context)


def run_screenshot_loop(context, pcap_path, type_mapping, ip_version, target_ip, test_label="Respond"):
    """
    Loop over ICMP type mappings and take terminal + Wireshark screenshots.
    Used for both Respond-to and Send tests.
    """
    if ip_version == 4:
        ip_dst = f"ip.dst == {target_ip}"
        ip_src = f"ip.src == {target_ip}"
        icmp_req = "icmp.type"
        icmp_rep = "icmp.type"
        unreachable_type = 3
        label = "IPv4"
    else:
        ip_dst = f"ipv6.dst == {target_ip}"
        ip_src = f"ipv6.src == {target_ip}"
        icmp_req = "icmpv6.type"
        icmp_rep = "icmpv6.type"
        unreachable_type = 1
        label = "IPv6"

    for req_type, expected_reply in type_mapping.items():

        # 1. Clear terminal and print header
        StepRunner([CommandStep("tester", "clear")]).run(context)
        header_cmd = f"echo -e '\\n=== {test_label}: Auditing {label} ICMP Type {req_type} ==='"
        StepRunner([CommandStep("tester", header_cmd)]).run(context)

        # 2. Define the tshark filter
        tshark_filter = (
            f"({ip_dst} and {icmp_req} == {req_type}) or "
            f"({ip_src} and ({icmp_rep} == {expected_reply} or {icmp_rep} == {unreachable_type}))"
        )

        # 3a. Run tshark visibly in tmux
        tshark_cmd = f"tshark -r {pcap_path} -Y '{tshark_filter}'"
        StepRunner([CommandStep("tester", tshark_cmd)]).run(context)
        time.sleep(2)

        # 3b. Take the terminal screenshot
        StepRunner([ScreenshotStep(
            terminal="tester",
            suffix=f"{test_label.lower()}_ipv{ip_version}_type_{req_type}"
        )]).run(context)

        # 4a. Analyze PCAP for matching frames
        StepRunner([AnalyzePcapStep(filter_expr=tshark_filter)]).run(context)

        # 4b. Open Wireshark with full display filter
        if context.matched_frame:
            StepRunner([WiresharkPacketScreenshotStep(
                suffix=f"{test_label.lower()}_ipv{ip_version}_type_{req_type}",
                display_filter=tshark_filter
            )]).run(context)
        else:
            print(f"[*] No packets for {label} Type {req_type} ({test_label}). Skipping Wireshark.")


# ---------------------------------------------------------------------------
#  SEND TESTS (Trigger DuT to generate ICMP, capture on our machine)
# ---------------------------------------------------------------------------

def run_send_capture_cycle(context, ip_version, dut_ip, pcap_filename):
    """
    Start PCAP, SSH into OpenWRT (DuT) to trigger ICMP Send conditions, wait, stop PCAP.
    Triggers all Send-type ICMP packets from the DuT.
    """
    openwrt_ip = context.openwrt_ip
    openwrt_pass = context.openwrt_password
    sudo_pass = context.sudo_password or ""
    kali_ip = context.dut_ip  # Kali's IP (where we capture)

    if not openwrt_ip or not openwrt_pass:
        print("[-] OpenWRT credentials not provided. Skipping Send tests.")
        return False

    # 1. Start PCAP (capture packets FROM DuT)
    StepRunner([PcapStartStep(interface="eth0", filename=pcap_filename)]).run(context)

    # 2. Authenticate sudo on Kali
    StepRunner([CommandStep("tester", f"echo '{sudo_pass}' | sudo -S true")]).run(context)
    time.sleep(1)

    if ip_version == 4:
        _trigger_ipv4_send(context, openwrt_ip, openwrt_pass, kali_ip, sudo_pass)
    else:
        _trigger_ipv6_send(context, openwrt_ip, openwrt_pass, kali_ip, sudo_pass)

    # 3. Wait for all responses to arrive
    time.sleep(15)

    # 4. Stop PCAP
    StepRunner([PcapStopStep()]).run(context)
    return True


def _trigger_ipv4_send(context, openwrt_ip, openwrt_pass, kali_ip, sudo_pass):
    """Trigger IPv4 ICMP Send conditions on OpenWRT."""

    # Type 8 (Echo Request) - Send: Permitted
    # SSH into OpenWRT and ping Kali
    print("[*] Triggering Type 8 (Echo Request): OpenWRT pings Kali")
    cmd = f"sshpass -p '{openwrt_pass}' ssh -o StrictHostKeyChecking=no root@{openwrt_ip} 'ping -c 5 -W 2 {kali_ip}'"
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(6)

    # Type 3 (Destination Unreachable) - Send: Permitted
    # Send packet to unreachable IP, OpenWRT should generate Type 3
    print("[*] Triggering Type 3 (Dest Unreachable): Sending to unreachable IP via OpenWRT")
    cmd = f"sudo ping -c 3 -W 2 192.168.99.99"
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(4)

    # Type 11 (Time Exceeded) - Send: Optional
    # Send packet with TTL=1 to OpenWRT, it should respond with Type 11
    print("[*] Triggering Type 11 (Time Exceeded): Sending TTL=1 packet")
    cmd = f"sudo python3 -c \"from scapy.all import *; send(IP(dst='{openwrt_ip}', ttl=1)/ICMP())\""
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(3)

    # Type 12 (Parameter Problem) - Send: Permitted
    # Send packet with invalid IP header options
    print("[*] Triggering Type 12 (Parameter Problem): Sending malformed IP options")
    cmd = f"sudo python3 -c \"from scapy.all import *; send(IP(dst='{openwrt_ip}', options=IPOption(b'\\x99\\x00\\x00\\x00'))/ICMP())\""
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(3)

    # Type 5 (Redirect) - Send: NOT PERMITTED
    # We just capture — if OpenWRT sends Type 5, it FAILS compliance
    print("[*] Monitoring for Type 5 (Redirect): Should NOT be sent by DuT")

    # Type 14 (Timestamp Reply) - Send: NOT PERMITTED
    # Send Timestamp Request, OpenWRT should NOT reply
    print("[*] Triggering Type 14 check (Timestamp Reply): Should NOT be sent")
    cmd = f"sudo python3 -c \"from scapy.all import *; send(IP(dst='{openwrt_ip}')/ICMP(type=13))\""
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(3)


def _trigger_ipv6_send(context, openwrt_ip, openwrt_pass, kali_ip, sudo_pass):
    """Trigger IPv6 ICMP Send conditions on OpenWRT."""

    openwrt_ipv6 = context.openwrt_ipv6 or openwrt_ip
    kali_ipv6 = context.dut_ipv6 or kali_ip

    # Type 128 (Echo Request) - Send: Permitted
    print("[*] Triggering Type 128 (Echo Request): OpenWRT pings Kali IPv6")
    cmd = f"sshpass -p '{openwrt_pass}' ssh -o StrictHostKeyChecking=no root@{openwrt_ip} 'ping6 -c 5 -W 2 {kali_ipv6}'"
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(6)

    # Type 1 (Destination Unreachable) - Send: Permitted
    print("[*] Triggering Type 1 (Dest Unreachable): Sending to unreachable IPv6")
    cmd = f"sudo ping6 -c 3 -W 2 fd00:dead:beef::99"
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(4)

    # Type 2 (Packet Too Big) - Send: Permitted
    print("[*] Triggering Type 2 (Packet Too Big): Sending oversized packet")
    cmd = f"sudo python3 -c \"from scapy.all import *; send(IPv6(dst='{openwrt_ipv6}')/ICMPv6EchoRequest()/Raw(b'A'*2000))\""
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(3)

    # Type 3 (Time Exceeded) - Send: Optional
    print("[*] Triggering Type 3 (Time Exceeded): Sending hop-limit=1 packet")
    cmd = f"sudo python3 -c \"from scapy.all import *; send(IPv6(dst='{openwrt_ipv6}', hlim=1)/ICMPv6EchoRequest())\""
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(3)

    # Type 4 (Parameter Problem) - Send: Permitted
    print("[*] Triggering Type 4 (Parameter Problem): Sending malformed IPv6")
    cmd = f"sudo python3 -c \"from scapy.all import *; send(IPv6(dst='{openwrt_ipv6}', nh=255)/Raw(b'\\x00'*40))\""
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(3)

    # Type 135 (Neighbour Solicitation) - Send: Permitted
    print("[*] Triggering Type 135 (Neighbour Solicitation): Probing OpenWRT")
    cmd = f"sudo python3 -c \"from scapy.all import *; send(IPv6(dst='{openwrt_ipv6}')/ICMPv6ND_NS(tgt='{openwrt_ipv6}'))\""
    StepRunner([CommandStep("tester", cmd)]).run(context)
    time.sleep(3)

    # Type 137 (Redirect) - Send: NOT PERMITTED
    print("[*] Monitoring for Type 137 (Redirect): Should NOT be sent by DuT")


def get_send_mapping_ipv4():
    """ITSAR Send compliance mapping for IPv4 ICMP types."""
    return {
        # type: (expected_reply, permitted_status)
        # Permitted to Send:
        8:  8,   # Echo Request (DuT sends Type 8)
        3:  3,   # Destination Unreachable (DuT sends Type 3)
        11: 11,  # Time Exceeded (DuT sends Type 11)
        12: 12,  # Parameter Problem (DuT sends Type 12)
        0:  0,   # Echo Reply (DuT sends as reply)
    }


def get_send_mapping_ipv6():
    """ITSAR Send compliance mapping for IPv6 ICMP types."""
    return {
        128: 128,  # Echo Request (DuT sends Type 128)
        1:   1,    # Destination Unreachable (DuT sends Type 1)
        2:   2,    # Packet Too Big (DuT sends Type 2)
        3:   3,    # Time Exceeded (DuT sends Type 3)
        4:   4,    # Parameter Problem (DuT sends Type 4)
        135: 135,  # Neighbour Solicitation (DuT sends Type 135)
        136: 136,  # Neighbour Advertisement (DuT sends Type 136)
    }


def run_send_screenshot_loop(context, pcap_path, ip_version, dut_ip):
    """
    Screenshot loop specifically for Send tests.
    Captures packets FROM the DuT (OpenWRT).
    """
    if ip_version == 4:
        send_mapping = get_send_mapping_ipv4()
        ip_src = f"ip.src == {dut_ip}"
        icmp_field = "icmp.type"
        label = "IPv4"
    else:
        send_mapping = get_send_mapping_ipv6()
        ip_src = f"ipv6.src == {dut_ip}"
        icmp_field = "icmpv6.type"
        label = "IPv6"

    for icmp_type, _ in send_mapping.items():

        # 1. Clear terminal and print header
        StepRunner([CommandStep("tester", "clear")]).run(context)
        header_cmd = f"echo -e '\\n=== SEND TEST: {label} ICMP Type {icmp_type} from DuT ==='"
        StepRunner([CommandStep("tester", header_cmd)]).run(context)

        # 2. Filter: packets FROM DuT with this ICMP type
        tshark_filter = f"({ip_src} and {icmp_field} == {icmp_type})"

        # 3a. Run tshark visibly
        tshark_cmd = f"tshark -r {pcap_path} -Y '{tshark_filter}'"
        StepRunner([CommandStep("tester", tshark_cmd)]).run(context)
        time.sleep(2)

        # 3b. Take terminal screenshot
        StepRunner([ScreenshotStep(
            terminal="tester",
            suffix=f"send_ipv{ip_version}_type_{icmp_type}"
        )]).run(context)

        # 4a. Analyze PCAP
        StepRunner([AnalyzePcapStep(filter_expr=tshark_filter)]).run(context)

        # 4b. Open Wireshark if packets found
        if context.matched_frame:
            StepRunner([WiresharkPacketScreenshotStep(
                suffix=f"send_ipv{ip_version}_type_{icmp_type}",
                display_filter=tshark_filter
            )]).run(context)
            print(f"[+] DuT SENT {label} Type {icmp_type} ✓ (Permitted)")
        else:
            print(f"[*] DuT did NOT send {label} Type {icmp_type} (not observed)")


def check_not_permitted_send(context, pcap_path, ip_version, dut_ip):
    """
    Verify DuT does NOT send ICMP types that are NOT PERMITTED per ITSAR.
    Returns list of violations.
    """
    violations = []

    if ip_version == 4:
        ip_src = f"ip.src == {dut_ip}"
        icmp_field = "icmp.type"
        not_permitted = {
            5: "Redirect",
            14: "Timestamp Reply",
        }
    else:
        ip_src = f"ipv6.src == {dut_ip}"
        icmp_field = "icmpv6.type"
        not_permitted = {
            137: "Redirect",
        }

    for icmp_type, name in not_permitted.items():
        StepRunner([CommandStep("tester", "clear")]).run(context)
        header_cmd = f"echo -e '\\n=== NOT PERMITTED CHECK: Type {icmp_type} ({name}) ==='"
        StepRunner([CommandStep("tester", header_cmd)]).run(context)

        tshark_filter = f"({ip_src} and {icmp_field} == {icmp_type})"
        tshark_cmd = f"tshark -r {pcap_path} -Y '{tshark_filter}'"
        StepRunner([CommandStep("tester", tshark_cmd)]).run(context)
        time.sleep(2)

        # Screenshot the result
        StepRunner([ScreenshotStep(
            terminal="tester",
            suffix=f"notpermitted_ipv{ip_version}_type_{icmp_type}"
        )]).run(context)

        # Check if any packets matched (violation!)
        StepRunner([AnalyzePcapStep(filter_expr=tshark_filter)]).run(context)
        if context.matched_frame:
            print(f"[✗] VIOLATION: DuT sent NOT PERMITTED Type {icmp_type} ({name})!")
            StepRunner([WiresharkPacketScreenshotStep(
                suffix=f"notpermitted_ipv{ip_version}_type_{icmp_type}",
                display_filter=tshark_filter
            )]).run(context)
            violations.append(icmp_type)
        else:
            print(f"[✓] PASS: DuT did NOT send Type {icmp_type} ({name})")

    return violations


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
        print("[⚠] WARNING: 0 packets captured! ICMP packets may not have been sent.")
        print("[⚠] Ensure sudo works without password prompt in tmux.")
        return "INCONCLUSIVE"

    return "PASS"
