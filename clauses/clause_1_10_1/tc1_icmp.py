from core.testcase import TestCase
from clauses.clause_1_10_1.icmp_helpers import (
    run_capture_cycle, run_screenshot_loop, validate_pcap,
    run_send_capture_cycle, run_send_screenshot_loop,
    check_not_permitted_send, check_not_permitted_respond,
    check_not_permitted_process,
    get_respond_mapping_ipv4,
)
from datetime import datetime
import os


class TC1ICMPIPv4(TestCase):
    def __init__(self):
        super().__init__("TC1_ICMP_IPV4",
                         "IPv4 ICMP handling compliance test (Send + Respond + Process)")

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

        all_violations = []

        # ===================================================================
        # PART 1: RESPOND-TO TESTS
        # Per ETSI: Send ICMP to DuT, verify it responds (or does NOT respond)
        # ===================================================================
        print("\n[=== PART 1: RESPOND-TO TESTS (IPv4) ===]")

        # 1a. Run PCAP capture cycle (icmp_forge.py sends all ICMP types to DuT)
        run_capture_cycle(context, "--ipv4", ipv4_target, "icmp_ipv4_respond.pcapng", log_file)
        respond_pcap = context.pcap_file

        # 1b. Screenshot types where Respond To = Optional/Permitted
        #     Per ETSI: Only Type 8 (Echo Request) has Respond To = Optional
        ipv4_respond_mapping = get_respond_mapping_ipv4()
        run_screenshot_loop(context, respond_pcap, ipv4_respond_mapping,
                            ip_version=4, target_ip=ipv4_target, test_label="Respond")

        # 1c. Check types where Respond To = Not Permitted
        #     Per ETSI: Type 13 (Timestamp) — DuT should NOT respond with Type 14
        respond_violations = check_not_permitted_respond(
            context, respond_pcap, ip_version=4, dut_ip=ipv4_target)
        all_violations.extend(respond_violations)

        # Validate Respond PCAP
        respond_status = validate_pcap(context, respond_pcap)

        # ===================================================================
        # PART 2: SEND TESTS
        # Per ETSI: Trigger DuT to generate ICMP, verify it sends correct types
        # ===================================================================
        print("\n[=== PART 2: SEND TESTS (IPv4) ===]")

        openwrt_ip = context.openwrt_ip
        if not openwrt_ip:
            print("[-] No OpenWRT IP provided. Skipping Send tests.")
            self.status = respond_status if not all_violations else "FAIL"
            return self

        # 2a. Run Send capture cycle (SSH into OpenWRT, trigger ICMP)
        send_ok = run_send_capture_cycle(context, ip_version=4, dut_ip=openwrt_ip,
                                         pcap_filename="icmp_ipv4_send.pcapng")

        if send_ok:
            send_pcap = context.pcap_file

            # 2b. Screenshot permitted Send types (Type 0, 3, 8, 11, 12)
            run_send_screenshot_loop(context, send_pcap, ip_version=4, dut_ip=openwrt_ip)

            # 2c. Check Send = Not Permitted (Type 14: Timestamp Reply)
            send_violations = check_not_permitted_send(
                context, send_pcap, ip_version=4, dut_ip=openwrt_ip)
            all_violations.extend(send_violations)

            # Validate Send PCAP
            send_status = validate_pcap(context, send_pcap)
        else:
            send_status = "INCONCLUSIVE"

        # ===================================================================
        # PART 3: PROCESS TESTS (Configuration Changes)
        # Per ETSI: Type 5 (Redirect) — DuT should NOT change routing config
        # ===================================================================
        print("\n[=== PART 3: PROCESS TESTS (IPv4) ===]")

        process_violations = check_not_permitted_process(
            context, ip_version=4, dut_ip=ipv4_target)
        all_violations.extend(process_violations)

        # ===================================================================
        # FINAL STATUS
        # ===================================================================
        if all_violations:
            print(f"\n[FAIL] {len(all_violations)} violation(s) found: {all_violations}")
            self.status = "FAIL"
        elif respond_status == "INCONCLUSIVE" or send_status == "INCONCLUSIVE":
            self.status = "INCONCLUSIVE"
        else:
            self.status = "PASS"

        return self
