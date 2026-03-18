from core.testcase import TestCase
from clauses.clause_1_10_1.icmp_helpers import (
    run_capture_cycle, run_screenshot_loop, validate_pcap,
    run_send_capture_cycle, run_send_screenshot_loop, check_not_permitted_send
)
from datetime import datetime
import os


class TC1ICMPIPv4(TestCase):
    def __init__(self):
        super().__init__("TC1_ICMP_IPV4", "IPv4 ICMP type filtering compliance test (Respond + Send)")

    def run(self, context):
        context.current_testcase = self
        print(f"\n--- Running {self.name} ---")

        ipv4_target = context.dut_ip
        if not ipv4_target:
            print("[-] No IPv4 address provided. Skipping test case.")
            self.status = "SKIPPED"
            return self

        # Setup log path
        path = context.evidence.testcase_dir(context.clause, self)
        timestamp = datetime.now().strftime("%Y_%m_%d_%H-%M-%S")
        log_file = os.path.join(path, "logs", f"{timestamp}_icmp_ipv4.txt")

        # ===================================================================
        # PART 1: RESPOND-TO TESTS (We send ICMP to DuT, check response)
        # ===================================================================
        print("\n[=== PART 1: RESPOND-TO TESTS (IPv4) ===]")

        # Run PCAP capture cycle (send ICMP via icmp_forge.py)
        run_capture_cycle(context, "--ipv4", ipv4_target, "icmp_ipv4_respond.pcapng", log_file)

        # Map: Request Type -> Expected Reply Type (IPv4)
        ipv4_respond_mapping = {
            0:  0,   # Echo Reply
            3:  3,   # Destination Unreachable
            5:  5,   # Redirect
            8:  0,   # Echo Request -> Echo Reply
            11: 11,  # Time Exceeded
            12: 12,  # Parameter Problem
            13: 14,  # Timestamp Request -> Timestamp Reply
            14: 14,  # Timestamp Reply
        }

        # Run screenshot loop for Respond-to tests
        run_screenshot_loop(context, context.pcap_file, ipv4_respond_mapping,
                            ip_version=4, target_ip=ipv4_target, test_label="Respond")

        # Validate Respond PCAP
        respond_status = validate_pcap(context, context.pcap_file)

        # ===================================================================
        # PART 2: SEND TESTS (Trigger DuT to generate ICMP, capture on Kali)
        # ===================================================================
        print("\n[=== PART 2: SEND TESTS (IPv4) ===]")

        openwrt_ip = context.openwrt_ip
        if not openwrt_ip:
            print("[-] No OpenWRT IP provided. Skipping Send tests.")
            self.status = respond_status
            return self

        # Run Send capture cycle (SSH into OpenWRT, trigger ICMP)
        send_ok = run_send_capture_cycle(context, ip_version=4, dut_ip=openwrt_ip,
                                         pcap_filename="icmp_ipv4_send.pcapng")

        if send_ok:
            # Screenshot loop for Send tests (packets FROM OpenWRT)
            run_send_screenshot_loop(context, context.pcap_file, ip_version=4, dut_ip=openwrt_ip)

            # Check NOT PERMITTED types (should NOT be sent by DuT)
            violations = check_not_permitted_send(context, context.pcap_file, ip_version=4, dut_ip=openwrt_ip)

            # Validate Send PCAP
            send_status = validate_pcap(context, context.pcap_file)

            # Determine overall status
            if violations:
                print(f"\n[✗] FAIL: DuT sent {len(violations)} NOT PERMITTED ICMP types: {violations}")
                self.status = "FAIL"
            elif respond_status == "INCONCLUSIVE" or send_status == "INCONCLUSIVE":
                self.status = "INCONCLUSIVE"
            else:
                self.status = "PASS"
        else:
            self.status = respond_status

        return self
