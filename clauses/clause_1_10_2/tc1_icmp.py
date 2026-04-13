from core.testcase import TestCase
from clauses.clause_1_10_2.icmp_helpers import (
    run_unified_send_tests,
    check_not_permitted_process,
    setup_routing, teardown_routing,
)


class TC1ICMPIPv4(TestCase):
    def __init__(self):
        super().__init__("TC1_ICMP_IPV4",
                         "IPv4 ICMP handling compliance test (Send + Process)")

    def run(self, context):
        context.current_testcase = self
        print(f"\n--- Running {self.name} ---")

        dut_ip = context.dut_ip
        if not dut_ip:
            print("[-] No IPv4 address provided. Skipping test case.")
            self.status = "SKIPPED"
            return self

        all_violations = []

        # ===================================================================
        # ROUTING SETUP
        # Route nonsense IP and auxiliary IP through OpenWRT so the router
        # can generate ICMP errors (Dest Unreachable, Time Exceeded, Redirect)
        # ===================================================================
        setup_routing(context, ip_version=4)

        # ===================================================================
        # SEND TESTS (Unified)
        # Each test sends a purposeful packet and expects a specific
        # response (or lack thereof) from the DuT (OpenWRT router).
        # ===================================================================
        print("\n[=== SEND TESTS (IPv4) ===]")
        send_violations, pcap_status = run_unified_send_tests(context, ip_version=4)
        all_violations.extend(send_violations)

        # ===================================================================
        # PROCESS TESTS (Configuration Changes)
        # Verify DuT does NOT change routing config when receiving
        # ICMP Redirect (Type 5).
        # ===================================================================
        print("\n[=== PROCESS TESTS (IPv4) ===]")
        process_violations = check_not_permitted_process(
            context, ip_version=4, dut_ip=dut_ip)
        all_violations.extend(process_violations)

        # ===================================================================
        # ROUTING TEARDOWN
        # ===================================================================
        teardown_routing(context, ip_version=4)

        # ===================================================================
        # FINAL STATUS
        # ===================================================================
        if all_violations:
            print(f"\n[FAIL] {len(all_violations)} violation(s) found: {all_violations}")
            self.status = "FAIL"
        elif pcap_status == "INCONCLUSIVE":
            self.status = "INCONCLUSIVE"
        else:
            self.status = "PASS"

        return self
