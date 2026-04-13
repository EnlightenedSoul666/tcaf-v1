from core.testcase import TestCase
from clauses.clause_1_10_2.icmp_helpers import (
    run_unified_send_tests,
    check_not_permitted_process,
    setup_routing, teardown_routing,
)


class TC2ICMPIPv6(TestCase):
    def __init__(self):
        super().__init__("TC2_ICMP_IPV6",
                         "IPv6 ICMP handling compliance test (Send + Process)")

    def run(self, context):
        context.current_testcase = self
        print(f"\n--- Running {self.name} ---")

        dut_ipv6 = context.dut_ipv6
        if not dut_ipv6:
            print("[-] No IPv6 address provided. Skipping test case.")
            self.status = "SKIPPED"
            return self

        all_violations = []

        # ===================================================================
        # ROUTING SETUP
        # Route nonsense IPv6 and auxiliary IPv6 through OpenWRT so the
        # router can generate ICMPv6 errors (Dest Unreachable, Time Exceeded)
        # ===================================================================
        setup_routing(context, ip_version=6)

        # ===================================================================
        # SEND TESTS (Unified)
        # Each test sends a purposeful packet and expects a specific
        # response (or lack thereof) from the DuT (OpenWRT router).
        # ===================================================================
        print("\n[=== SEND TESTS (IPv6) ===]")
        send_violations, pcap_status = run_unified_send_tests(context, ip_version=6)
        all_violations.extend(send_violations)

        # ===================================================================
        # PROCESS TESTS (Configuration Changes)
        # Verify DuT does NOT change routing config when receiving
        # ICMPv6 Redirect (137), Router Solicitation (133), or
        # Router Advertisement (134).
        # ===================================================================
        print("\n[=== PROCESS TESTS (IPv6) ===]")
        process_violations = check_not_permitted_process(
            context, ip_version=6, dut_ip=dut_ipv6)
        all_violations.extend(process_violations)

        # ===================================================================
        # ROUTING TEARDOWN
        # ===================================================================
        teardown_routing(context, ip_version=6)

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
