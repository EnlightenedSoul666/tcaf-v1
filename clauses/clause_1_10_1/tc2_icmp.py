from core.testcase import TestCase
from clauses.clause_1_10_1.icmp_helpers import (
    run_capture_cycle, run_screenshot_loop, validate_pcap,
    run_send_capture_cycle, run_send_screenshot_loop,
    check_not_permitted_send, check_not_permitted_respond,
    check_not_permitted_process,
    get_respond_mapping_ipv6,
)
from datetime import datetime
import os


class TC2ICMPIPv6(TestCase):
    def __init__(self):
        super().__init__("TC2_ICMP_IPV6",
                         "IPv6 ICMP handling compliance test (Send + Respond + Process)")

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

        all_violations = []

        # ===================================================================
        # PART 1: RESPOND-TO TESTS
        # Per ETSI: Send ICMPv6 to DuT, verify it responds (or does NOT)
        # ===================================================================
        print("\n[=== PART 1: RESPOND-TO TESTS (IPv6) ===]")

        # 1a. Run PCAP capture cycle (icmp_forge.py sends all ICMPv6 types to DuT)
        run_capture_cycle(context, "--ipv6", ipv6_target, "icmp_ipv6_respond.pcapng", log_file)
        respond_pcap = context.pcap_file

        # 1b. Screenshot types where Respond To = Optional/Permitted
        #     Per ETSI: Type 128 (Echo Request) = Optional
        #               Type 135 (Neighbour Solicitation) = Permitted
        ipv6_respond_mapping = get_respond_mapping_ipv6()
        run_screenshot_loop(context, respond_pcap, ipv6_respond_mapping,
                            ip_version=6, target_ip=ipv6_target, test_label="Respond")

        # 1c. Check types where Respond To = Not Permitted
        #     Per ETSI: Type 133 (Router Solicitation) — DuT should NOT respond
        respond_violations = check_not_permitted_respond(
            context, respond_pcap, ip_version=6, dut_ip=ipv6_target)
        all_violations.extend(respond_violations)

        # Validate Respond PCAP
        respond_status = validate_pcap(context, respond_pcap)

        # ===================================================================
        # PART 2: SEND TESTS
        # Per ETSI: Trigger DuT to generate ICMPv6, verify correct types sent
        # ===================================================================
        print("\n[=== PART 2: SEND TESTS (IPv6) ===]")

        openwrt_ip = context.openwrt_ip
        if not openwrt_ip:
            print("[-] No OpenWRT IP provided. Skipping Send tests.")
            self.status = respond_status if not all_violations else "FAIL"
            return self

        # 2a. Run Send capture cycle (SSH into OpenWRT, trigger ICMPv6)
        send_ok = run_send_capture_cycle(context, ip_version=6, dut_ip=openwrt_ip,
                                         pcap_filename="icmp_ipv6_send.pcapng")

        if send_ok:
            # Use OpenWRT's IPv6 for filtering packets FROM OpenWRT
            openwrt_ipv6 = context.openwrt_ipv6 or openwrt_ip
            send_pcap = context.pcap_file

            # 2b. Screenshot permitted Send types (129, 1, 128, 3, 4, 2, 135, 136)
            run_send_screenshot_loop(context, send_pcap, ip_version=6, dut_ip=openwrt_ipv6)

            # 2c. Check Send = Not Permitted
            #     Per ETSI: No IPv6 types have Send = Not Permitted
            #     (137 Redirect has Process = Not Permitted, not Send)
            send_violations = check_not_permitted_send(
                context, send_pcap, ip_version=6, dut_ip=openwrt_ipv6)
            all_violations.extend(send_violations)

            # Validate Send PCAP
            send_status = validate_pcap(context, send_pcap)
        else:
            send_status = "INCONCLUSIVE"

        # ===================================================================
        # PART 3: PROCESS TESTS (Configuration Changes)
        # Per ETSI: Types 137 (Redirect), 133 (RS), 134 (RA) —
        #           DuT should NOT change config when receiving these
        # ===================================================================
        print("\n[=== PART 3: PROCESS TESTS (IPv6) ===]")

        process_violations = check_not_permitted_process(
            context, ip_version=6, dut_ip=ipv6_target)
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
