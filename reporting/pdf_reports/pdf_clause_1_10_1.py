"""
ReportLab PDF — ITSAR Clause 1.10.1: ICMP Type Filtering Compliance.

12-section ITSAR-format native PDF with:
  - Cover page with banners + metadata + OVERALL RESULT
  - ICMP type mapping tables (permitted / not permitted)
  - Per-test-case 7-field breakdown (a-g)
  - Compliance analysis table mapping ICMP types to test results
  - Recommendations
"""

import os
import datetime

from reportlab.lib import colors
from reportlab.platypus import Spacer, PageBreak, Table, TableStyle, Paragraph

from reporting.pdf_base import (
    PDFReportBase, W,
    build_cover_page, section_header, sub_heading, sub_sub_heading,
    body, bullet, output_block, results_table, stats_row,
    compliance_table, recommendation_box, info_box, metadata_table,
    testbed_diagram, build_tc_detail, find_screenshots_for_tc,
    verdict_color, build_styles,
    C_TABLE_HDR, C_WHITE, C_ROW_ALT, C_GRID, C_PASS, C_FAIL,
    C_LIGHT_BLUE, C_ACCENT, C_MID_BLUE,
    mm, ParagraphStyle, TA_CENTER,
)


def _per_type_results_table(results, styles):
    """Build a detailed per-ICMP-type PASS/FAIL table from sub_results."""
    hdr_s = ParagraphStyle(
        "pth", fontName="Helvetica-Bold", fontSize=9,
        textColor=colors.white, alignment=TA_CENTER,
    )
    cell_s = styles["TableCell"]

    data = [[
        Paragraph("ICMP Type", hdr_s),
        Paragraph("Name", hdr_s),
        Paragraph("IP Version", hdr_s),
        Paragraph("Test Category", hdr_s),
        Paragraph("Restriction", hdr_s),
        Paragraph("PASS/FAIL", hdr_s),
    ]]

    all_sub = []
    for tc in results:
        for sr in getattr(tc, "sub_results", []):
            all_sub.append(sr)

    if not all_sub:
        return []

    # Sort by ip_version, then test_type, then icmp_type
    all_sub.sort(key=lambda s: (s.get("ip_version", 0),
                                 s.get("test_type", ""),
                                 s.get("icmp_type", 0)))

    from reporting.pdf_base import C_PASS, C_FAIL
    for sr in all_sub:
        status = sr.get("status", "N/A")
        sc = C_PASS if status == "PASS" else C_FAIL
        data.append([
            Paragraph(str(sr.get("icmp_type", "?")), cell_s),
            Paragraph(sr.get("icmp_name", "Unknown"), cell_s),
            Paragraph(f"IPv{sr.get('ip_version', '?')}", cell_s),
            Paragraph(sr.get("test_type", "?"), cell_s),
            Paragraph(sr.get("category", "?"), cell_s),
            Paragraph(
                f"<b>{status}</b>",
                ParagraphStyle("pt_v", fontName="Helvetica-Bold", fontSize=9,
                               textColor=sc, alignment=TA_CENTER),
            ),
        ])

    tbl = Table(data,
                colWidths=[18*mm, 42*mm, 22*mm, 25*mm, 28*mm, 22*mm],
                repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), C_TABLE_HDR),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("GRID",           (0, 0), (-1, -1), 0.4, C_GRID),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",     (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
    ]))
    return [tbl]


class PDFClause1101Report(PDFReportBase):

    CLAUSE_ID    = "1.10.1"
    HEADER_TITLE = "ICMP TYPE FILTERING COMPLIANCE TEST REPORT  |  ITSAR 1.10.1"

    def _icmp_reference_tables(self, styles):
        """Build the ETSI ICMP type reference tables (Permitted + Not Permitted)."""
        items = []

        hdr_s = ParagraphStyle(
            "icmp_th", fontName="Helvetica-Bold", fontSize=9,
            textColor=colors.white, alignment=TA_CENTER,
        )
        cell_s = styles["TableCell"]

        # ── Permitted Types ───────────────────────────
        items += sub_heading("Permitted ICMP Types (per ETSI TS 133 117 Table)", styles)

        permitted_data = [
            [Paragraph("IPv4 Type", hdr_s), Paragraph("IPv6 Type", hdr_s),
             Paragraph("Name", hdr_s), Paragraph("Send", hdr_s),
             Paragraph("Respond To", hdr_s)],
            # Data rows
            ["0",   "128", "Echo Reply",                "Optional",  "N/A"],
            ["3",   "1",   "Destination Unreachable",   "Permitted", "N/A"],
            ["8",   "129", "Echo Request",              "Permitted", "Optional"],
            ["11",  "3",   "Time Exceeded",             "Optional",  "N/A"],
            ["12",  "4",   "Parameter Problem",         "Permitted", "N/A"],
            ["N/A", "2",   "Packet Too Big",            "Permitted", "N/A"],
            ["N/A", "135", "Neighbour Solicitation",    "Permitted", "Permitted"],
            ["N/A", "136", "Neighbour Advertisement",   "Permitted", "N/A"],
        ]
        # Convert data rows to Paragraphs
        for i in range(1, len(permitted_data)):
            permitted_data[i] = [Paragraph(c, cell_s) for c in permitted_data[i]]

        pt = Table(permitted_data,
                   colWidths=[22 * mm, 22 * mm, 50 * mm, 28 * mm, 28 * mm],
                   repeatRows=1)
        pt.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), C_TABLE_HDR),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
            ("GRID",           (0, 0), (-1, -1), 0.4, C_GRID),
            ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",     (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
        ]))
        items.append(pt)
        items.append(Spacer(1, 4 * mm))

        # ── Not Permitted Types ───────────────────────
        items += sub_heading("Not Permitted ICMP Types", styles)

        np_data = [
            [Paragraph("IPv4 Type", hdr_s), Paragraph("IPv6 Type", hdr_s),
             Paragraph("Name", hdr_s), Paragraph("Send", hdr_s),
             Paragraph("Respond To", hdr_s), Paragraph("Process", hdr_s)],
            ["5",   "137", "Redirect",              "N/A",           "N/A",           "Not Permitted"],
            ["13",  "N/A", "Timestamp Request",     "N/A",           "Not Permitted", "N/A"],
            ["14",  "N/A", "Timestamp Reply",       "Not Permitted", "N/A",           "N/A"],
            ["N/A", "133", "Router Solicitation",   "N/A",           "Not Permitted", "Not Permitted"],
            ["N/A", "134", "Router Advertisement",  "N/A",           "N/A",           "Not Permitted"],
        ]
        for i in range(1, len(np_data)):
            np_data[i] = [Paragraph(c, cell_s) for c in np_data[i]]

        npt = Table(np_data,
                    colWidths=[20 * mm, 20 * mm, 42 * mm, 24 * mm, 28 * mm, 28 * mm],
                    repeatRows=1)
        npt.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), C_TABLE_HDR),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
            ("GRID",           (0, 0), (-1, -1), 0.4, C_GRID),
            ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",     (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
        ]))
        items.append(npt)
        items.append(Spacer(1, 4 * mm))

        return items

    def build_story(self, context, results, styles):
        now     = datetime.datetime.now()
        total, passed, failed, errors = self.count_results(results)
        overall = self.compute_overall(results)

        story = []

        # ── COVER PAGE ────────────────────────────────────────────────────
        story += build_cover_page(
            clause_title="ICMP Type Filtering Compliance Verification",
            clause_subtitle="ITSAR Clause 1.10.1 -- ICMPv4/ICMPv6 Packet Handling",
            meta_rows=[
                ("ITSAR Clause",     "1.10.1"),
                ("ETSI Reference",   "ETSI TS 133 117 V17.2.0, Section 4.2.4.1.1.2"),
                ("TSDSI Reference",  "TSDSI STD T1.3GPP 33.117-17.2.0 V.1.0.0"),
                ("Test Date",        now.strftime("%B %d, %Y")),
                ("Test Time",        now.strftime("%H:%M:%S")),
                ("DUT IP (IPv4)",    getattr(context, "dut_ip", "N/A")),
                ("DUT IP (IPv6)",    getattr(context, "dut_ipv6", "N/A") or "N/A"),
                ("DUT Model",        getattr(context, "dut_model", "N/A")),
                ("DUT Firmware",     getattr(context, "dut_firmware", "N/A")),
                ("OpenWRT IP",       getattr(context, "openwrt_ip", "N/A") or "N/A"),
                ("Tester System",    "Linux-based tester (Kali/Ubuntu)"),
                ("Total Test Cases", str(total)),
            ],
            overall=overall,
            styles=styles,
        )

        # ── 1. Access and Authorization ───────────────────────────────────
        story += section_header("1. Access and Authorization", styles)
        story += body(
            "This section verifies that the DUT correctly handles ICMP and ICMPv6 "
            "packets according to ITSAR requirements. Processing of ICMP packet types "
            "which are not required for operation shall be disabled on the CPE.",
            styles)

        # ── 2. Requirement Description ────────────────────────────────────
        story += section_header("2. Requirement Description", styles)
        story.append(info_box(
            "<b>Clause Requirement (ITSAR 2.10.2 / ETSI TS 133 117):</b><br/><br/>"
            "Processing of ICMPv4 and ICMPv6 packets which are not required for operation "
            "shall be disabled on the CPE. In particular, there are certain types of ICMPv4 and "
            "ICMPv6 that are not used in most networks, but represent a risk.<br/><br/>"
            "The tester sends ICMP packets of various types to the DUT and verifies that:<br/>"
            "-- <b>Permitted</b> types receive appropriate responses<br/>"
            "-- <b>Not Permitted</b> types are silently dropped (no response, no config change)<br/>"
            "-- The DUT does not <b>Send</b> forbidden types unsolicited<br/>"
            "-- The DUT does not <b>Process</b> forbidden types (e.g., Redirect, RA, RS)",
            styles))
        story.append(Spacer(1, 4))

        # ICMP reference tables
        story += self._icmp_reference_tables(styles)

        # ── 3. DUT Configuration ──────────────────────────────────────────
        story += section_header("3. DUT Configuration", styles)
        story += sub_heading("3.1 DUT Details", styles)
        story.append(metadata_table([
            ("Device",           getattr(context, "dut_model", "N/A")),
            ("Serial Number",    getattr(context, "dut_serial", "N/A")),
            ("Firmware Version", getattr(context, "dut_firmware", "N/A")),
            ("DUT IPv4 Address", getattr(context, "dut_ip", "N/A")),
            ("DUT IPv6 Address", getattr(context, "dut_ipv6", "N/A") or "N/A"),
            ("OpenWRT IPv4",     getattr(context, "openwrt_ip", "N/A") or "N/A"),
            ("OpenWRT IPv6",     getattr(context, "openwrt_ipv6", "N/A") or "N/A"),
        ], styles))
        story.append(Spacer(1, 4))

        story += sub_heading("3.2 Network Topology", styles)
        story += body(
            "The test uses a three-device topology: Tester (Kali/Ubuntu), DUT (OpenWRT router), "
            "and a third host (auxiliary machine) for redirect/routing tests. All devices are on "
            "the same bridged network segment.", styles)

        # ── 4. Preconditions ──────────────────────────────────────────────
        story += section_header("4. Preconditions", styles)
        for b in [
            "The tester system has network connectivity to the DUT.",
            "The DUT IPv4 and IPv6 addresses are reachable from the tester.",
            "The tester system has Scapy, tcpdump, tshark, and Wireshark installed.",
            "The tester has root/sudo privileges for raw packet injection.",
            "For Process tests: a third host and routing configuration are available.",
        ]:
            story.append(bullet(b, styles))
        story.append(Spacer(1, 4))

        # ── 5. Test Objective ─────────────────────────────────────────────
        story += section_header("5. Test Objective", styles)
        story += body(
            "To verify that the DUT correctly filters ICMP and ICMPv6 packet types "
            "according to the ITSAR/ETSI requirements. The tester crafts and sends various "
            "ICMP type packets to the DUT using Scapy, captures both the request and response "
            "using tcpdump, and analyzes the pcap with tshark to determine whether the DUT "
            "allows, responds to, or blocks each type.", styles)

        # ── 6. Test Scenario ──────────────────────────────────────────────
        story += section_header("6. Test Scenario", styles)

        story += sub_heading("6.1 Number of Test Scenarios", styles)
        story += body(
            f"A total of {total} test case(s) were executed covering three categories: "
            "Respond To (does the DUT reply?), Send (does the DUT originate?), and "
            "Process (does the DUT change configuration?).", styles)

        story += sub_heading("6.2 Test Bed Diagram", styles)
        story.append(testbed_diagram(
            f"Tester (Scapy)\n{getattr(context, 'tester_ip', 'Kali Linux')}",
            "<-- ICMP/ICMPv6 -->",
            f"DUT (OpenWRT)\n{getattr(context, 'openwrt_ip', 'N/A')}",
            styles,
        ))
        story.append(Spacer(1, 4))

        story += sub_heading("6.3 Network Fundamentals", styles)
        story += sub_sub_heading("IPv4 and IPv6 Subnet Basics", styles)
        story += body(
            "All devices in this test topology reside on the same IPv4 private subnet "
            "(10.208.207.0/24) and share an IPv6 Unique Local Address (ULA) prefix "
            "(fdd4:48ab:15e6::/60). IPv4 addresses are manually configured (static) or "
            "assigned via DHCP from the OpenWRT router. IPv6 addresses are auto-configured "
            "via SLAAC (Stateless Address Auto-Configuration): the router sends Router "
            "Advertisements containing the subnet prefix, and each host derives its own "
            "address by combining the prefix with its MAC-based interface identifier.",
            styles)

        story += sub_sub_heading("Router Solicitation and Router Advertisement", styles)
        story += body(
            "When an IPv6-enabled host boots, it sends a Router Solicitation (ICMPv6 Type 133) "
            "to discover on-link routers; the router replies with a Router Advertisement "
            "(ICMPv6 Type 134) containing prefix, MTU, and default-gateway information. "
            "This exchange enables zero-configuration IPv6 networking, unlike IPv4 which "
            "requires either a DHCP server or manual static configuration.",
            styles)

        story += sub_sub_heading("Routing Setup for ICMP Tests", styles)
        story += body(
            "To test Send and Process categories, the tester adds static routes so that "
            "packets destined for the auxiliary machine and the nonsense IP travel through "
            "the OpenWRT router instead of directly to the target. This forces OpenWRT to "
            "generate ICMP errors (Destination Unreachable, Time Exceeded, Redirect) that "
            "would not occur on a flat L2 segment. Traceroutes are captured before and after "
            "route setup to evidence the path change.",
            styles)

        story += sub_sub_heading("How ICMP Redirect Is Triggered", styles)
        story += body(
            "An ICMP Redirect (Type 5 / ICMPv6 Type 137) is generated by a router when it "
            "receives a packet and the best next-hop for that destination is on the same "
            "interface the packet arrived on. The router forwards the packet but sends a "
            "Redirect back to the sender, advising it to send future packets directly to "
            "the better gateway. If the DUT processes this Redirect, its routing table changes "
            "silently -- a security risk that ETSI prohibits.",
            styles)

        story += sub_sub_heading("Caution with ip route Commands", styles)
        story += body(
            "Incorrect static routes can black-hole traffic or create routing loops. "
            "For example, adding a route with a gateway that is itself unreachable will cause "
            "all matching packets to be silently dropped. Adding overlapping routes without "
            "proper metric values can lead to unpredictable path selection. The test framework "
            "always cleans up (deletes) added routes in the teardown phase to prevent residual "
            "misrouting.",
            styles)

        story += sub_sub_heading("VM Boot Order", styles)
        story += body(
            "The host VM (Kali tester) should be started first, followed by OpenWRT. "
            "This ensures Kali obtains its IP address from the host machine's Windows network "
            "(via the bridged adapter) rather than from OpenWRT's DHCP pool. If OpenWRT boots "
            "first, Kali may receive its default gateway from OpenWRT instead of from the "
            "Windows host, which can isolate the tester from the external network.",
            styles)
        story.append(Spacer(1, 4))

        story += sub_heading("6.4 Tools Required", styles)
        for tool in ["Scapy (ICMP packet crafting and injection)",
                     "tcpdump (packet capture on tester interface)",
                     "tshark (pcap analysis and filtering)",
                     "Wireshark (visual packet evidence)",
                     "Linux-based tester system with root privileges"]:
            story.append(bullet(tool, styles))
        story.append(Spacer(1, 4))

        story += sub_heading("6.5 Test Execution Steps", styles)
        for step in [
            "Start packet capture on the tester interface using tcpdump.",
            "Send each ICMP type packet to the DUT using Scapy's icmp_forge module.",
            "Wait for DUT responses (timeout for not-permitted types).",
            "Stop the packet capture.",
            "Analyze the captured pcap using tshark to verify request/response pairs.",
            "Take Wireshark screenshots showing the request and response packets.",
            "For Send tests: trigger the DUT to generate specific ICMP types.",
            "For Process tests: send forbidden types and verify no configuration change.",
        ]:
            story.append(bullet(step, styles))
        story.append(Spacer(1, 4))

        # ── 7. Expected Results ───────────────────────────────────────────
        story += section_header("7. Expected Results for Pass", styles)
        story += body(
            "The DUT should respond to Permitted ICMP types (e.g., Echo Request/Reply, "
            "Neighbour Solicitation/Advertisement) and silently drop Not Permitted types "
            "(e.g., Timestamp, Redirect, Router Solicitation/Advertisement). The DUT shall "
            "not originate forbidden Send types and shall not process forbidden Process types.",
            styles)

        story.append(PageBreak())

        # ── 8. Test Execution ─────────────────────────────────────────────
        story += section_header("8. Test Execution", styles)

        for idx, tc in enumerate(results, start=1):
            name   = getattr(tc, "name", f"TC{idx}")
            desc   = getattr(tc, "description", name)
            status = getattr(tc, "status", "N/A")

            story += sub_heading(f"8.{idx} Test Case: {name}", styles)

            # Collect evidence
            ev_files = []
            for ev in getattr(tc, "evidence", []):
                ss = ev.get("screenshot") if isinstance(ev, dict) else getattr(ev, "screenshot", None)
                if ss and os.path.exists(ss):
                    ev_files.append(ss)
            ev_files += find_screenshots_for_tc(context, self.CLAUSE_ID, name)

            story += build_tc_detail(
                tc_num=f"8.{idx}",
                tc_id=name,
                tc_name=desc,
                description=desc,
                input_cmd=getattr(tc, "input_cmd", "scapy + tcpdump"),
                expected=getattr(tc, "expected",
                                 "Permitted types get responses; Not Permitted types are dropped"),
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
                f"The following test case(s) did not pass: {', '.join(failed_names)}. "
                "This indicates that the DUT may not be filtering all ICMP types as "
                "required by the ITSAR/ETSI specification. The DUT may be responding to "
                "or processing forbidden ICMP types.", styles)
        else:
            story += body(
                "All ICMP type filtering test cases passed successfully. The DUT correctly "
                "handles the tested ICMPv4 and ICMPv6 packet types in accordance with the "
                "ITSAR/ETSI requirements. Permitted types receive responses, and Not Permitted "
                "types are silently dropped.", styles)
        story.append(Spacer(1, 4))

        # ── 10. Test Case Results ─────────────────────────────────────────
        story += section_header("10. Test Case Results", styles)

        story += sub_heading("10.1 Overall Test Case Summary", styles)
        story.append(results_table(results, styles))
        story.append(Spacer(1, 6 * mm))
        story.append(stats_row(total, passed, failed, overall, styles))
        story.append(Spacer(1, 6 * mm))

        # Per-ICMP-type detailed results
        per_type_items = _per_type_results_table(results, styles)
        if per_type_items:
            story += sub_heading("10.2 Per-ICMP-Type Detailed Results", styles)
            story += body(
                "The table below shows the individual PASS/FAIL result for each ICMP type "
                "tested across all categories (Respond To, Send, Process). Each row represents "
                "a single ICMP type check.",
                styles)
            story += per_type_items
            story.append(Spacer(1, 6 * mm))

        # ── 11. Compliance Analysis ───────────────────────────────────────
        story += section_header("11. Compliance Analysis", styles)

        checks = []
        for tc in results:
            name   = getattr(tc, "name", "?")
            status = getattr(tc, "status", "N/A")
            desc   = getattr(tc, "description", name)
            checks.append((desc[:70], name, status))

        # Add high-level compliance checks
        checks.append((
            "Not Permitted types are silently dropped",
            "All TCs (Not Permitted subset)",
            overall,
        ))
        checks.append((
            "Permitted types receive correct responses",
            "All TCs (Permitted subset)",
            overall,
        ))

        if checks:
            story.append(compliance_table(checks, styles))
        story.append(Spacer(1, 6 * mm))

        # ── 12. Conclusion ────────────────────────────────────────────────
        story += section_header("12. Conclusion", styles)
        if overall == "PASS":
            story += body(
                f"All {total} test case(s) passed. The DUT correctly implements ICMP "
                "type filtering as prescribed by ITSAR clause 1.10.1 and ETSI TS 133 117. "
                "Forbidden ICMP types are silently dropped, and the DUT does not originate "
                "or process them.", styles)
        else:
            story += body(
                f"The test run identified {failed} failing test case(s) and {errors} "
                "error(s). The DUT does NOT fully comply with the ICMP type filtering "
                "requirements. The DUT may respond to, originate, or process forbidden "
                "ICMP types. Remediation is required.", styles)

        story.append(recommendation_box(
            "<b>Recommendations:</b><br/>"
            "-- Configure the DUT firewall to drop ICMPv4 Type 5 (Redirect), 13 (Timestamp), "
            "and 14 (Timestamp Reply).<br/>"
            "-- Configure the DUT to drop ICMPv6 Type 133 (Router Solicitation), 134 (Router "
            "Advertisement), and 137 (Redirect).<br/>"
            "-- Ensure the DUT does not originate Timestamp Reply (Type 14) packets.<br/>"
            "-- Verify that processing of Redirect, RS, and RA packets is disabled.<br/>"
            "-- Re-run this test suite after any firewall or routing configuration change.",
            styles))

        return story
