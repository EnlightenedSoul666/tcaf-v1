from core.testcase import TestCase
from clauses.clause_1_10_2.icmp_helpers import (
    run_unified_send_tests,
    check_not_permitted_process,
    setup_routing, teardown_routing,
)
from clauses.clause_1_10_2.ptb_test import PTBTest


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
        # DEDICATED PACKET TOO BIG TEST
        # Focuses specifically on ICMPv6 Type 2 (PTB) by:
        #   1. Reducing OpenWRT's egress MTU (br-lan to 1280)
        #   2. Sending 1400-byte packet to auxiliary machine
        #   3. Capturing Type 2 response from DuT
        #   4. Restoring original MTU
        # Per RFC 8200: PTB is generated when packet size > outgoing MTU.
        # ===================================================================
        print("\n[=== DEDICATED PTB TEST (IPv6 Type 2) ===]")
        ptb_test = PTBTest(context)
        ptb_status = ptb_test.run()
        # PTB is Optional per ETSI (Type 2 Permitted, not Required),
        # so INCONCLUSIVE is acceptable. Only FAIL on violation.
        context.current_testcase.sub_results.append({
            "test_type": "Send",
            "icmp_type": 2,
            "icmp_name": "Packet Too Big (Dedicated MTU Test)",
            "ip_version": 6,
            "status": ptb_status,
            "category": "Permitted",
            "description": (
                f"ICMPv6 Type 2 - Dedicated PTB Test: Reduces OpenWRT's br-lan "
                f"MTU to 1280 bytes and sends a 1400-byte ICMPv6 Echo Request to "
                f"the auxiliary machine (Metasploitable) at {context.auxiliary_ipv6}. "
                f"OpenWRT must forward the packet, detect the MTU mismatch (1400 > 1280), "
                f"and emit ICMPv6 Type 2 Code 0 (Packet Too Big) back to the tester. "
                f"Per RFC 8200 Section 4.2, IPv6 forbids in-flight fragmentation, so "
                f"the router MUST notify the sender of the MTU limitation. Per ETSI "
                f"TS 133 117, Type 2 is Permitted (not Required); INCONCLUSIVE is "
                f"acceptable if no PTB is seen (lab may not have asymmetric MTU paths). "
                f"Result: {ptb_status}. Original MTU restored after test."
            ),
        })

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
