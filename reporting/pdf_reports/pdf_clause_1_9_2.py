"""
ReportLab PDF — ITSAR Clause 1.9.2: Open Port Compliance.

12-section ITSAR-format native PDF with:
  - Cover page with banners + metadata + OVERALL RESULT
  - Per-test-case 7-field breakdown (a-g) for each scan type
  - Compliance analysis table
  - Recommendations
"""

import os
import datetime

from reportlab.platypus import Spacer, PageBreak

from reporting.pdf_base import (
    PDFReportBase, W,
    build_cover_page, section_header, sub_heading, body, bullet,
    output_block, results_table, stats_row, compliance_table,
    recommendation_box, info_box, metadata_table, testbed_diagram,
    build_tc_detail, find_screenshots_for_tc, verdict_color,
    mm, ParagraphStyle, TA_CENTER,
)


class PDFClause192Report(PDFReportBase):

    CLAUSE_ID    = "1.9.2"
    HEADER_TITLE = "OPEN PORT COMPLIANCE TEST REPORT  |  ITSAR 1.9.2"

    # Map test case names to scan info
    SCAN_TYPES = {
        "TC1_TCP_SCAN":  ("TCP SYN Scan",    "nmap -sS -p- -Pn -n -T4"),
        "TC2_UDP_SCAN":  ("UDP Scan",         "nmap -sU -p- -Pn -n -T4"),
        "TC3_SCTP_SCAN": ("SCTP INIT Scan",   "nmap -sY -p- -Pn -n -T4"),
    }

    def build_story(self, context, results, styles):
        now     = datetime.datetime.now()
        total, passed, failed, errors = self.count_results(results)
        overall = self.compute_overall(results)

        story = []

        # ── COVER PAGE ────────────────────────────────────────────────────
        story += build_cover_page(
            clause_title="Open Port Compliance Verification",
            clause_subtitle="ITSAR Clause 1.9.2 -- Transport Layer Port Scanning",
            meta_rows=[
                ("ITSAR Clause",     "1.9.2"),
                ("Requirement",      "Open Port Compliance"),
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
            "This section verifies that only vendor-documented and operationally "
            "necessary ports respond to external requests on the DUT's network interfaces.",
            styles)

        # ── 2. Requirement Description ────────────────────────────────────
        story += section_header("2. Requirement Description", styles)
        story.append(info_box(
            "<b>Clause Requirement:</b><br/>"
            "It shall be ensured that on all network interfaces, only vendor documented/"
            "identified ports on the transport layer respond to requests from outside the "
            "system. The list of identified open ports shall match the list of network services "
            "that are necessary for the operation of the CPE.",
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

        # ── 4. Preconditions ──────────────────────────────────────────────
        story += section_header("4. Preconditions", styles)
        for b in [
            "The tester system has network connectivity to the DUT.",
            f"The DUT IPv4 address ({getattr(context, 'dut_ip', 'N/A')}) is reachable from the tester.",
            "The tester system has nmap, tcpdump, tshark, and Wireshark installed.",
            "The tester has sufficient privileges (root/sudo) to run SYN, UDP, and SCTP scans.",
        ]:
            story.append(bullet(b, styles))
        story.append(Spacer(1, 4))

        # ── 5. Test Objective ─────────────────────────────────────────────
        story += section_header("5. Test Objective", styles)
        story += body(
            "To identify all open ports on the DUT using TCP SYN, UDP, and SCTP INIT "
            "scan techniques. The discovered open ports are documented with packet "
            "capture evidence showing the request and response for each open port.",
            styles)

        # ── 6. Test Scenario ──────────────────────────────────────────────
        story += section_header("6. Test Scenario", styles)

        story += sub_heading("6.1 Number of Test Scenarios", styles)
        story += body(
            f"A total of {total} scan type(s) were executed: TCP SYN, UDP, and SCTP INIT "
            "scans across all 65535 ports.", styles)

        story += sub_heading("6.2 Test Bed Diagram", styles)
        story.append(testbed_diagram(
            f"Tester (nmap)\n{getattr(context, 'tester_ip', 'Linux Tester')}",
            "<-- TCP/UDP/SCTP -->",
            f"DUT\n{getattr(context, 'dut_ip', 'N/A')}",
            styles,
        ))
        story.append(Spacer(1, 4))

        story += sub_heading("6.3 Tools Required", styles)
        for tool in ["nmap (port scanning)", "tcpdump (packet capture)",
                     "tshark (packet analysis)", "Wireshark (visual evidence)",
                     "Linux-based tester system with root privileges"]:
            story.append(bullet(tool, styles))
        story.append(Spacer(1, 4))

        story += sub_heading("6.4 Test Execution Steps", styles)
        for step in [
            "Start packet capture on the tester interface using tcpdump.",
            "Run nmap scan against the DUT for all 65535 ports (TCP SYN, UDP, SCTP INIT).",
            "Stop the packet capture after each scan completes.",
            "Parse nmap output to identify open ports and services.",
            "Take Wireshark screenshots for each discovered open port showing request/response.",
        ]:
            story.append(bullet(step, styles))
        story.append(Spacer(1, 4))

        # ── 7. Expected Results ───────────────────────────────────────────
        story += section_header("7. Expected Results for Pass", styles)
        story += body(
            "Only documented and operationally necessary service ports should be found open. "
            "The packet captures should show SYN/SYN-ACK (TCP), response packets (UDP), "
            "or INIT/INIT-ACK (SCTP) for each open port. No undocumented ports should respond.",
            styles)

        story.append(PageBreak())

        # ── 8. Test Execution ─────────────────────────────────────────────
        story += section_header("8. Test Execution", styles)

        for idx, tc in enumerate(results, start=1):
            name   = getattr(tc, "name", f"TC{idx}")
            desc   = getattr(tc, "description", name)
            status = getattr(tc, "status", "N/A")

            scan_label, scan_cmd = self.SCAN_TYPES.get(name, (name, "nmap"))
            full_cmd = f"{scan_cmd} {getattr(context, 'dut_ip', 'N/A')}"

            story += sub_heading(f"8.{idx} Test Case: {name}", styles)

            # Collect evidence files
            ev_files = []
            for ev in getattr(tc, "evidence", []):
                ss = ev.get("screenshot") if isinstance(ev, dict) else getattr(ev, "screenshot", None)
                if ss and os.path.exists(ss):
                    ev_files.append(ss)
            ev_files += find_screenshots_for_tc(context, self.CLAUSE_ID, name)

            story += build_tc_detail(
                tc_num=f"8.{idx}",
                tc_id=name,
                tc_name=f"{scan_label} -- {desc}",
                description=f"Perform {scan_label} on all 65535 ports of the DUT to identify open services.",
                input_cmd=full_cmd,
                expected="Only vendor-documented ports should be open.",
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
                f"The following scan(s) did not complete successfully or found unexpected "
                f"open ports: {', '.join(failed_names)}. Review the evidence to determine "
                f"if undocumented ports are open on the DUT.", styles)
        else:
            story += body(
                "All port scanning test cases completed successfully. The open ports "
                "discovered on the DUT have been documented with packet capture evidence "
                "for compliance review. Only expected services were found responsive.",
                styles)
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
            name   = getattr(tc, "name", "?")
            status = getattr(tc, "status", "N/A")
            scan_label, _ = self.SCAN_TYPES.get(name, (name, ""))
            checks.append((
                f"Only documented ports respond ({scan_label})",
                name,
                status,
            ))
        if checks:
            story.append(compliance_table(checks, styles))
        story.append(Spacer(1, 6 * mm))

        # ── 12. Conclusion ────────────────────────────────────────────────
        story += section_header("12. Conclusion", styles)
        if overall == "PASS":
            story += body(
                f"All {total} scan(s) completed successfully. The DUT exposes only "
                "vendor-documented and operationally necessary ports, in compliance "
                "with ITSAR clause 1.9.2.", styles)
        else:
            story += body(
                f"The test identified {failed} failed scan(s). The DUT may expose "
                "undocumented or unnecessary ports. Remediation is required before "
                "the DUT can be considered compliant with ITSAR clause 1.9.2.", styles)

        story.append(recommendation_box(
            "<b>Recommendations:</b><br/>"
            "-- Close all unnecessary TCP/UDP/SCTP ports on the DUT.<br/>"
            "-- Ensure only vendor-documented services are running.<br/>"
            "-- Apply firewall rules to restrict access to management interfaces.<br/>"
            "-- Disable any debug or development services in production firmware.<br/>"
            "-- Re-run this test suite after any configuration change to verify compliance.",
            styles))

        return story
