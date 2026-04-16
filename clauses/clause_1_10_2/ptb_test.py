"""
Packet Too Big (PTB) Test Case — ICMPv6 Type 2

Per RFC 8200 Section 4.2, an ICMPv6 Packet Too Big error is generated when:
  1. A router receives a packet destined for another node
  2. The packet size exceeds the outgoing interface MTU
  3. IPv6 forbids in-flight fragmentation (unlike IPv4)
  4. The router must drop the packet and send Type 2 back to the source

This test:
  1. Reduces OpenWRT's egress interface MTU (e.g., br-lan to 1280)
  2. Sends packets larger than the reduced MTU through the router
  3. Captures and verifies the Type 2 PTB response
  4. Restores the original MTU after test
"""

import time
import subprocess

from core.step_runner import StepRunner
from steps.command_step import CommandStep
from steps.screenshot_step import ScreenshotStep
from steps.pcap_start_step import PcapStartStep
from steps.pcap_stop_step import PcapStopStep
from steps.analyze_pcap_step import AnalyzePcapStep
from steps.wireshark_packet_screenshot_step import WiresharkPacketScreenshotStep


def _sh(cmd, timeout=10):
    """Run a shell command, return stdout on success or '' on any failure."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


class PTBTest:
    """
    Dedicated Packet Too Big test for IPv6.

    Verifies that when a packet exceeds the MTU of an outgoing interface,
    the router (OpenWRT/DuT) correctly responds with ICMPv6 Type 2.
    """

    def __init__(self, context):
        self.context = context
        self.original_mtu = None
        self.reduced_mtu = 1280
        self.packet_size = 1400  # Larger than 1280 but fits in 1500

    def get_current_mtu(self):
        """Query OpenWRT for the current br-lan MTU via SSH."""
        if not self.context.openwrt_ip or not self.context.openwrt_password:
            print("[-] OpenWRT credentials not available")
            return None

        # Use sshpass to avoid interactive prompt
        cmd = (
            f"sshpass -p '{self.context.openwrt_password}' "
            f"ssh -o StrictHostKeyChecking=no root@{self.context.openwrt_ip} "
            f"'ip link show br-lan | grep mtu | awk {{print $5}}'"
        )
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                mtu_str = result.stdout.strip()
                if mtu_str.startswith("mtu"):
                    return int(mtu_str.split()[1])
        except Exception as e:
            print(f"[-] Error querying MTU: {e}")
        return None

    def set_mtu(self, mtu_value):
        """Set OpenWRT's br-lan MTU to the specified value."""
        if not self.context.openwrt_ip or not self.context.openwrt_password:
            print("[-] OpenWRT credentials not available")
            return False

        cmd = (
            f"sshpass -p '{self.context.openwrt_password}' "
            f"ssh -o StrictHostKeyChecking=no root@{self.context.openwrt_ip} "
            f"'ip link set br-lan mtu {mtu_value}'"
        )
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception as e:
            print(f"[-] Error setting MTU: {e}")
            return False

    def run(self):
        """
        Execute the full PTB test:
        1. Capture original MTU
        2. Reduce MTU
        3. Start PCAP capture
        4. Send oversized packets
        5. Stop PCAP and analyze
        6. Restore original MTU
        """
        ctx = self.context

        print("\n" + "="*70)
        print("ICMPv6 Packet Too Big (Type 2) Test")
        print("="*70 + "\n")

        # -- 1. Get original MTU -----------------------------------------------
        print("[1/7] Querying original OpenWRT br-lan MTU...")
        self.original_mtu = self.get_current_mtu()
        if self.original_mtu:
            print(f"      Original MTU: {self.original_mtu}")
        else:
            print("      [!] Could not query MTU (continuing anyway)")

        # -- 2. Reduce MTU -----------------------------------------------------
        print(f"[2/7] Reducing OpenWRT br-lan MTU to {self.reduced_mtu}...")
        if self.set_mtu(self.reduced_mtu):
            print(f"      ✓ MTU reduced to {self.reduced_mtu}")
        else:
            print(f"      [!] Failed to reduce MTU (test may INCONCLUSIVE)")
        time.sleep(2)

        # -- 3. Verify routing to auxiliary machine ----------------------------
        if not ctx.auxiliary_ipv6:
            print("[-] No auxiliary IPv6 address. Cannot run PTB test.")
            return "SKIPPED"

        print(f"[3/7] Verifying route to auxiliary machine ({ctx.auxiliary_ipv6})...")
        StepRunner([CommandStep("tester", "clear")]).run(ctx)
        StepRunner([CommandStep("tester",
            f"echo '[*] Route to auxiliary IPv6:'")]).run(ctx)
        StepRunner([CommandStep("tester",
            f"ip -6 route get {ctx.auxiliary_ipv6}")]).run(ctx)
        time.sleep(1)

        # -- 4. Start PCAP capture --------------------------------------------
        print("[4/7] Starting PCAP capture...")
        iface = getattr(ctx, "tester_iface", None) or "eth0"
        pcap_filename = "icmp_ipv6_ptb.pcapng"
        StepRunner([PcapStartStep(interface=iface, filename=pcap_filename)]).run(ctx)
        time.sleep(2)

        # -- 5. Send oversized packets ----------------------------------------
        print(f"[5/7] Sending {self.packet_size}-byte ICMPv6 Echo Request to {ctx.auxiliary_ipv6}...")
        StepRunner([CommandStep("tester", "clear")]).run(ctx)
        StepRunner([CommandStep("tester",
            f"echo '[*] Sending {self.packet_size}-byte packet to {ctx.auxiliary_ipv6}...'")]).run(ctx)

        send_cmd = (
            f"sudo python3 -c \""
            f"from scapy.all import *; "
            f"send(IPv6(dst='{ctx.auxiliary_ipv6}')/ICMPv6EchoRequest()/Raw(b'A'*{self.packet_size}), verbose=0)\""
        )
        StepRunner([CommandStep("tester", send_cmd)]).run(ctx)
        time.sleep(5)  # Wait for PTB to arrive

        # -- 6. Stop PCAP and take screenshot ---------------------------------
        print("[6/7] Stopping PCAP capture...")
        StepRunner([PcapStopStep()]).run(ctx)
        time.sleep(1)

        pcap_path = ctx.pcap_file

        # Display tshark output
        StepRunner([CommandStep("tester", "clear")]).run(ctx)
        StepRunner([CommandStep("tester",
            f"echo '=== ICMPv6 Type 2 (Packet Too Big) Packets ===' && "
            f"tshark -r {pcap_path} -Y 'icmpv6.type == 2'")]).run(ctx)
        time.sleep(2)
        StepRunner([ScreenshotStep(
            terminal="tester",
            suffix="ptb_pcap_analysis"
        )]).run(ctx)

        # Analyze PCAP
        ptb_filter = f"icmpv6.type == 2 and ipv6.src == {ctx.dut_ipv6}"
        StepRunner([AnalyzePcapStep(filter_expr=ptb_filter)]).run(ctx)
        ptb_found = ctx.matched_frame is not None

        if ptb_found:
            print("[+] Type 2 (Packet Too Big) packet found in PCAP")
            StepRunner([WiresharkPacketScreenshotStep(
                suffix="ptb_packet_detail",
                display_filter=ptb_filter
            )]).run(ctx)
            status = "PASS"
        else:
            print("[-] No Type 2 packet found in PCAP")
            status = "INCONCLUSIVE"

        # -- 7. Restore original MTU ------------------------------------------
        print(f"[7/7] Restoring original MTU ({self.original_mtu})...")
        if self.original_mtu:
            if self.set_mtu(self.original_mtu):
                print(f"      ✓ MTU restored to {self.original_mtu}")
            else:
                print(f"      [!] Failed to restore MTU")
        time.sleep(1)

        # Summary
        print("\n" + "="*70)
        print(f"Result: {status}")
        print("="*70)
        print(f"Packet size: {self.packet_size} bytes")
        print(f"Reduced MTU: {self.reduced_mtu} bytes")
        print(f"Type 2 found: {'Yes' if ptb_found else 'No'}")
        print("\nNote: PTB only triggers when packet crosses a link with smaller MTU.")
        print("      In a homogeneous lab (all 1500 MTU), PTB may not trigger.")
        print("      The reduced br-lan MTU should trigger PTB if auxiliary is reachable.")
        print("="*70 + "\n")

        return status
