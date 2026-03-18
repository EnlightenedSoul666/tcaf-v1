from core.testcase import TestCase
from clauses.clause_1_10_1.icmp_helpers import (
    run_capture_cycle, run_screenshot_loop, validate_pcap,
    run_send_capture_cycle, run_send_screenshot_loop, check_not_permitted_send
)
from datetime import datetime
import os


class TC2ICMPIPv6(TestCase):
    def __init__(self):
        super().__init__("TC2_ICMP_IPV6", "IPv6 ICMP type filtering compliance test (Respond + Send)")

    def run(self, context):
        context.current_testcase = self
        print(f"\n--- Running {self.name} ---")

        ipv6_target = context.dut_ipv6
        if not ipv6_target:
            print("[-] No IPv6 address provided. Skipping test case.")
            self.status = "SKIPPED"
            return self

        # Setup log path
        path = context.evidence.testcase_dir(context.clause, self)
        timestamp = datetime.now().strftime("%Y_%m_%d_%H-%M-%S")
        log_file = os.path.join(path, "logs", f"{timestamp}_icmp_ipv6.txt")

        # ===================================================================
        # PART 1: RESPOND-TO TESTS (We send ICMP to DuT, check response)
        # ===================================================================
        print("\n[=== PART 1: RESPOND-TO TESTS (IPv6) ===]")

        # Run PCAP capture cycle (send ICMP via icmp_forge.py)
        run_capture_cycle(context, "--ipv6", ipv6_target, "icmp_ipv6_respond.pcapng", log_file)

        # Map: Request Type -> Expected Reply Type (ICMPv6)
        ipv6_respond_mapping = {
            128: 129,  # Echo Request -> Echo Reply
            129: 129,  # Echo Reply
            1:   1,    # Destination Unreachable
            2:   2,    # Packet Too Big
            3:   3,    # Time Exceeded
            4:   4,    # Parameter Problem
            133: 134,  # Router Solicitation -> Router Advertisement
            134: 134,  # Router Advertisement
            135: 136,  # Neighbour Solicitation -> Neighbour Advertisement
            136: 136,  # Neighbour Advertisement
            137: 137,  # Redirect
        }

        # Run screenshot loop for Respond-to tests
        run_screenshot_loop(context, context.pcap_file, ipv6_respond_mapping,
                            ip_version=6, target_ip=ipv6_target, test_label="Respond")

        # Validate Respond PCAP
        respond_status = validate_pcap(context, context.pcap_file)

        # ===================================================================
        # PART 2: SEND TESTS (Trigger DuT to generate ICMP, capture on Kali)
        # ===================================================================
        print("\n[=== PART 2: SEND TESTS (IPv6) ===]")

        openwrt_ip = context.openwrt_ip
        if not openwrt_ip:
            print("[-] No OpenWRT IP provided. Skipping Send tests.")
            self.status = respond_status
            return self

        # Run Send capture cycle (SSH into OpenWRT, trigger ICMPv6)
        send_ok = run_send_capture_cycle(context, ip_version=6, dut_ip=openwrt_ip,
                                         pcap_filename="icmp_ipv6_send.pcapng")

        if send_ok:
            # Use OpenWRT's IPv6 for filtering (packets FROM OpenWRT)
            openwrt_ipv6 = context.openwrt_ipv6 or openwrt_ip

            # Screenshot loop for Send tests (packets FROM OpenWRT)
            run_send_screenshot_loop(context, context.pcap_file, ip_version=6, dut_ip=openwrt_ipv6)

            # Check NOT PERMITTED types (should NOT be sent by DuT)
            violations = check_not_permitted_send(context, context.pcap_file, ip_version=6, dut_ip=openwrt_ipv6)

            # Validate Send PCAP
            send_status = validate_pcap(context, context.pcap_file)

            # Determine overall status
            if violations:
                print(f"\n[✗] FAIL: DuT sent {len(violations)} NOT PERMITTED ICMPv6 types: {violations}")
                self.status = "FAIL"
            elif respond_status == "INCONCLUSIVE" or send_status == "INCONCLUSIVE":
                self.status = "INCONCLUSIVE"
            else:
                self.status = "PASS"
        else:
            self.status = respond_status

        return self
