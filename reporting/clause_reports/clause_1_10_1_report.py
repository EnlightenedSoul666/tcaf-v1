import os
from docx import Document
from reporting.base_report import BaseReport


class Clause1101Report(BaseReport):
    """ITSAR Clause 1.10.1 — ICMP Type Filtering Compliance Report."""

    CLAUSE_ID = "1.10.1"

    def generate(self, context, results):
        doc = Document()

        self.add_page_number(doc)
        self.add_title(doc)

        # ── 1. DUT Details ──
        self.add_dut_details(doc, context, section_num="1")
        doc.add_paragraph()

        # ── 2. ITSAR Information ──
        self.add_itsar_heading(doc, "2. ITSAR Information", 2)

        table = doc.add_table(rows=3, cols=2)
        table.style = "Table Grid"
        for i, header in enumerate(["Field", "Value"]):
            cell = table.rows[0].cells[i]
            cell.text = header
            self.style_table_header(cell)

        table.rows[1].cells[0].text = "ITSAR Section"
        table.rows[1].cells[1].text = "1.10.1"
        table.rows[2].cells[0].text = "Requirement"
        table.rows[2].cells[1].text = "ICMP Type Filtering"

        self.add_data_cell_padding(table)
        self.prevent_table_row_split(table)
        doc.add_paragraph()

        # ── 3. Requirement Description ──
        self.add_itsar_heading(doc, "3. Requirement Description", 2)
        doc.add_paragraph(
            "Processing of ICMPv4 and ICMPv6 packets which are not required for operation "
            "shall be disabled on the CPE. In particular, there are certain types of ICMP4 and "
            "ICMPv6 that are not used in most networks, but represent a risk. Refer standards "
            "such as RFC 6192, RFC 7279, RFC 4890."
        )
        doc.add_paragraph()

        # ── 4. Preconditions ──
        self.add_itsar_heading(doc, "4. Preconditions", 2)
        doc.add_paragraph(
            "\u2022 The tester system has network connectivity to the DUT."
        )
        doc.add_paragraph(
            "\u2022 The DUT IPv4 address is reachable from the tester."
        )
        if getattr(context, "dut_ipv6", None):
            doc.add_paragraph(
                "\u2022 The DUT IPv6 address is reachable from the tester."
            )
        doc.add_paragraph(
            "\u2022 The tester system has Scapy, tcpdump, tshark, and Wireshark installed."
        )
        doc.add_paragraph()

        # ── 5. Test Objective ──
        self.add_itsar_heading(doc, "5. Test Objective", 2)
        doc.add_paragraph(
            "To verify that the DUT correctly filters ICMP and ICMPv6 packet types "
            "according to the ITSAR requirements. The tester sends various ICMP type "
            "packets to the DUT and captures both the request and the response to "
            "determine whether the DUT allows or blocks each type."
        )
        doc.add_paragraph()

        # ── 6. Test Scenario ──
        self.add_itsar_heading(doc, "6. Test Scenario", 2)

        self.add_itsar_subheading(doc, "6.1 Tools Required", 2)
        doc.add_paragraph("\u2022 Scapy (ICMP packet crafting)")
        doc.add_paragraph("\u2022 tcpdump (packet capture)")
        doc.add_paragraph("\u2022 tshark (packet analysis)")
        doc.add_paragraph("\u2022 Wireshark (visual evidence)")
        doc.add_paragraph("\u2022 Linux-based tester system")

        self.add_itsar_subheading(doc, "6.2 Test Execution Steps", 2)
        doc.add_paragraph(
            "\u2022 Start packet capture on the tester interface using tcpdump."
        )
        doc.add_paragraph(
            "\u2022 Send each ICMP type packet to the DUT using Scapy's icmp_forge.py."
        )
        doc.add_paragraph(
            "\u2022 Wait for DUT responses and stop the packet capture."
        )
        doc.add_paragraph(
            "\u2022 Analyze the captured pcap using tshark to verify request/response pairs."
        )
        doc.add_paragraph(
            "\u2022 Take Wireshark screenshots showing the request and response packets."
        )
        doc.add_paragraph()

        # ── 7. Expected Results ──
        self.add_itsar_heading(doc, "7. Expected Results", 2)
        doc.add_paragraph(
            "The DUT should respond to allowed ICMP types (e.g., Echo Request/Reply) "
            "and block or ignore disallowed ICMP types. The captured packets should "
            "show the expected filtering behavior for each ICMP type tested."
        )
        doc.add_paragraph()

        # ── 8. Test Execution ──
        self.add_itsar_heading(doc, "8. Test Execution", 2)

        for idx, tc in enumerate(results, start=1):
            h = self.add_itsar_subheading(doc, f"8.{idx} Test Case: {tc.name}", 2)
            self.keep_with_next(h)

            doc.add_paragraph(f"Description: {tc.description}")

            # Status with colour
            from reporting.base_report import GREEN, RED
            p   = doc.add_paragraph("Result: ")
            run = p.add_run(tc.status)
            run.bold           = True
            run.font.color.rgb = GREEN if tc.status.upper() == "PASS" else RED

            self.add_grey_horizontal_line(doc)

            # Embed evidence from test case
            for evidence in tc.evidence:
                screenshot = evidence.get("screenshot") if isinstance(evidence, dict) else getattr(evidence, "screenshot", None)
                if screenshot and os.path.exists(screenshot):
                    self.add_screenshot_block(
                        doc,
                        f"Evidence: {os.path.basename(screenshot)}",
                        screenshot,
                    )
                    doc.add_paragraph()

            # Also embed screenshots from the output directory
            self.embed_testcase_screenshots(
                doc, self.CLAUSE_ID, tc.name,
                label_prefix=f"TC{idx} — "
            )

        doc.add_paragraph()

        # ── 9. Test Observation ──
        self.add_itsar_heading(doc, "9. Test Observation", 2)

        failed = [tc for tc in results if tc.status.upper() != "PASS"]
        if failed:
            names = ", ".join(tc.name for tc in failed)
            doc.add_paragraph(
                f"The following test case(s) did not pass: {names}. "
                "This indicates that the DUT may not be filtering all ICMP types "
                "as required by the ITSAR specification."
            )
        else:
            doc.add_paragraph(
                "All ICMP type filtering test cases passed successfully. "
                "The DUT correctly handles the tested ICMP and ICMPv6 packet types "
                "in accordance with the ITSAR requirements."
            )
        doc.add_paragraph()

        # ── 10. Test Case Result Summary ──
        self.add_result_summary(doc, results, section_num="10")

        # Save
        report_path = self.get_report_path(self.CLAUSE_ID)
        doc.save(report_path)
        return report_path
