"""
ReportLab PDF — ITSAR Clause 1.1.1: CPE Authentication (SSH/HTTPS Crypto).

12-section ITSAR-format native PDF with:
  - Cover page with banners + metadata + OVERALL RESULT
  - Per-test-case 7-field breakdown (a-g)
  - Compliance analysis table
  - Recommendations
"""

import os
import datetime

from reportlab.platypus import Spacer, PageBreak

from reporting.pdf_base import (
    PDFReportBase, W,
    build_cover_page, section_header, sub_heading, body, bullet,
    label_value, output_block, tc_header_bar, verdict_banner,
    screenshot_block, results_table, stats_row, compliance_table,
    recommendation_box, info_box, metadata_table, testbed_diagram,
    build_tc_detail, find_screenshots_for_tc, verdict_color,
    mm, ParagraphStyle, TA_CENTER,
)


class PDFClause111Report(PDFReportBase):

    CLAUSE_ID    = "1.1.1"
    HEADER_TITLE = "CPE AUTHENTICATION COMPLIANCE TEST REPORT  |  ITSAR 1.1.1"

    def build_story(self, context, results, styles):
        now     = datetime.datetime.now()
        total, passed, failed, errors = self.count_results(results)
        overall = self.compute_overall(results)

        story = []

        # ── COVER PAGE ────────────────────────────────────────────────────
        story += build_cover_page(
            clause_title="CPE Authentication Compliance Verification",
            clause_subtitle="ITSAR Clause 1.1.1 -- Management Protocol Entity Mutual Authentication",
            meta_rows=[
                ("ITSAR Clause",     "1.1.1"),
                ("ITSAR Section",    getattr(context, "itsar_section", "1.1 Access and Authorization")),
                ("Requirement",      getattr(context, "itsar_requirement",
                                             "Management Protocols Entity Mutual Authentication")),
                ("Test Date",        now.strftime("%B %d, %Y")),
                ("Test Time",        now.strftime("%H:%M:%S")),
                ("DUT IP",           getattr(context, "dut_ip", "N/A")),
                ("DUT Model",        getattr(context, "dut_model", "N/A")),
                ("DUT Firmware",     getattr(context, "dut_firmware", "N/A")),
                ("Tester System",    "Linux-based tester"),
                ("Total Test Cases", str(total)),
            ],
            overall=overall,
            styles=styles,
        )

        # ── 1. Access and Authorization ───────────────────────────────────
        story += section_header("1. Access and Authorization", styles)
        story += body(
            "This section verifies that access to the DUT is restricted to authorized "
            "entities using secure communication mechanisms. The DUT shall communicate "
            "with authenticated management entities only.", styles)

        # ── 2. Requirement Description ────────────────────────────────────
        story += section_header("2. Requirement Description", styles)
        story.append(info_box(
            "<b>Clause Requirement:</b><br/>"
            "The CPE shall communicate with authenticated management entities only. "
            "The protocols used for the CPE management shall support mutual authentication "
            "mechanisms, preferably with pre-shared key arrangements or by equivalent entity "
            "mutual authentication mechanisms. This shall be verified for all protocols used "
            "for CPE management.<br/><br/>"
            "Secure communication mechanism between the Network product and the connected "
            "entities shall use only industry standard and NIST recommended cryptographic "
            "protocols such as IPSec, VPN, SSH, TLS/SSL, etc.",
            styles))
        story.append(Spacer(1, 4))

        # ── 3. DUT Configuration ──────────────────────────────────────────
        story += section_header("3. DUT Configuration", styles)
        story += sub_heading("3.1 DUT Details", styles)
        story.append(metadata_table([
            ("Device",           getattr(context, "dut_model", "N/A")),
            ("Serial Number",    getattr(context, "dut_serial", "N/A")),
            ("Firmware Version", getattr(context, "dut_firmware", "N/A")),
            ("DUT IP Address",   getattr(context, "dut_ip", "N/A")),
        ], styles))
        story.append(Spacer(1, 4))

        story += sub_heading("3.2 SSH Host Key Configuration", styles)
        story += body(
            "The tester system was configured to store the DUT's SSH host key in the "
            "known_hosts file, ensuring mutual authentication during SSH session establishment.",
            styles)

        # ── 4. Preconditions ──────────────────────────────────────────────
        story += section_header("4. Preconditions", styles)
        for b in [
            "The tester system has network connectivity to the DUT.",
            "SSH service is running on the DUT and accessible from the tester.",
            "The tester has nmap, tshark, Wireshark, and OpenSSH installed.",
            "HTTPS service is running on the DUT (if applicable).",
            "Network connectivity between tester and DUT is verified via ping.",
        ]:
            story.append(bullet(b, styles))
        story.append(Spacer(1, 4))

        # ── 5. Test Objective ─────────────────────────────────────────────
        story += section_header("5. Test Objective", styles)
        story += body(
            "To verify that the DUT management traffic is protected using secure "
            "cryptographic controls. The tester enumerates supported SSH/TLS algorithms, "
            "captures handshake traffic, verifies cipher strength against NIST/ITSAR "
            "requirements, and attempts weak algorithm negotiation to confirm rejection.",
            styles)

        # ── 6. Test Scenario ──────────────────────────────────────────────
        story += section_header("6. Test Scenario", styles)

        story += sub_heading("6.1 Number of Test Scenarios", styles)
        story += body(
            f"A total of {total} test case(s) were executed covering SSH cipher "
            "enumeration, secure handshake verification, and weak algorithm rejection.",
            styles)

        story += sub_heading("6.2 Test Bed Diagram", styles)
        story.append(testbed_diagram(
            f"Tester System\n{getattr(context, 'tester_ip', 'Linux Tester')}",
            "<-- SSH / HTTPS -->",
            f"DUT\n{getattr(context, 'dut_ip', 'N/A')}",
            styles,
        ))
        story.append(Spacer(1, 4))

        story += sub_heading("6.3 Tools Required", styles)
        for tool in ["Nmap (SSH/TLS cipher enumeration)", "Wireshark / tshark (packet capture)",
                     "OpenSSH (SSH client)", "openssl s_client (TLS testing)",
                     "Linux-based tester system"]:
            story.append(bullet(tool, styles))
        story.append(Spacer(1, 4))

        story += sub_heading("6.4 Test Execution Steps", styles)
        for step in [
            "Enumerate SSH algorithms using nmap --script ssh2-enum-algos.",
            "Capture SSH handshake traffic and verify cipher/KEX/MAC algorithms.",
            "Attempt SSH connection with deliberately weak ciphers to verify rejection.",
            "If HTTPS is available, enumerate TLS ciphers and capture Server Hello.",
            "Compare all observed algorithms against ITSAR/NIST approved lists.",
        ]:
            story.append(bullet(step, styles))
        story.append(Spacer(1, 4))

        # ── 7. Expected Results ───────────────────────────────────────────
        story += section_header("7. Expected Results for Pass", styles)
        story += body(
            "The DUT shall support only NIST-recommended cryptographic algorithms for SSH "
            "and TLS communication. Handshake captures shall show secure cipher negotiation. "
            "Attempts to connect with weak/deprecated algorithms shall be rejected by the DUT.",
            styles)

        story.append(PageBreak())

        # ── 8. Test Execution ─────────────────────────────────────────────
        story += section_header("8. Test Execution", styles)

        for idx, tc in enumerate(results, start=1):
            name = getattr(tc, "name", f"TC{idx}")
            desc = getattr(tc, "description", name)
            status = getattr(tc, "status", "N/A")

            story += sub_heading(f"8.{idx} Test Case: {name}", styles)

            # Collect evidence files
            ev_files = []
            for ev in getattr(tc, "evidence", []):
                ss = ev.get("screenshot") if isinstance(ev, dict) else getattr(ev, "screenshot", None)
                if ss and os.path.exists(ss):
                    ev_files.append(ss)
            # Also search output directory
            ev_files += find_screenshots_for_tc(context, self.CLAUSE_ID, name)

            story += build_tc_detail(
                tc_num=f"8.{idx}",
                tc_id=name,
                tc_name=desc,
                description=desc,
                input_cmd=getattr(tc, "input_cmd", ""),
                expected=getattr(tc, "expected", "DUT uses only secure algorithms"),
                actual_status=status,
                output_text=getattr(tc, "output", ""),
                verdict=status,
                evidence_files=ev_files,
                styles=styles,
            )

        story.append(PageBreak())

        # ── 9. Test Observation ───────────────────────────────────────────
        story += section_header("9. Test Observation", styles)
        failed_names = [getattr(tc, "name", "?") for tc in results
                        if getattr(tc, "status", "FAIL").upper() != "PASS"]
        if failed_names:
            story += body(
                f"It was observed that the DUT does not fully comply with the prescribed "
                f"secure cryptographic requirements. The failure was identified in the "
                f"following test case(s): {', '.join(failed_names)}. This indicates the DUT "
                f"may permit insecure cryptographic configurations.", styles)
        else:
            story += body(
                "It was observed that the DUT complies with the prescribed secure "
                "cryptographic requirements. All test cases related to secure cipher "
                "support, encrypted communication protection, and weak algorithm rejection "
                "have successfully passed.", styles)
        story.append(Spacer(1, 4))

        # ── 10. Test Case Results ─────────────────────────────────────────
        story += section_header("10. Test Case Results", styles)
        story.append(results_table(results, styles))
        story.append(Spacer(1, 6 * mm))
        story.append(stats_row(total, passed, failed, overall, styles))
        story.append(Spacer(1, 6 * mm))

        # ── 11. Compliance Analysis ───────────────────────────────────────
        story += section_header("11. Compliance Analysis", styles)

        checks = []
        for tc in results:
            name = getattr(tc, "name", "?")
            status = getattr(tc, "status", "N/A")
            desc = getattr(tc, "description", name)
            checks.append((desc[:70], name, status))

        if checks:
            story.append(compliance_table(checks, styles))
        story.append(Spacer(1, 6 * mm))

        # ── 12. Conclusion ────────────────────────────────────────────────
        story += section_header("12. Conclusion", styles)
        if overall == "PASS":
            story += body(
                f"All {total} test case(s) passed. The DUT correctly implements secure "
                "cryptographic protocols for management communication in accordance with "
                "ITSAR and NIST requirements.", styles)
        else:
            story += body(
                f"The test run identified {failed} failing test case(s) and {errors} "
                "error(s). The DUT does NOT fully comply with the secure cryptographic "
                "communication requirements. Remediation is required.", styles)

        story.append(recommendation_box(
            "<b>Recommendations:</b><br/>"
            "-- Ensure the DUT only enables NIST-recommended SSH ciphers, MAC, and KEX algorithms.<br/>"
            "-- Disable all weak/deprecated algorithms (DES, RC4, MD5, SHA1-based MACs, etc.).<br/>"
            "-- If HTTPS is available, enforce TLSv1.2+ with strong cipher suites only.<br/>"
            "-- Re-run this test suite after any configuration change to verify compliance.",
            styles))

        return story
