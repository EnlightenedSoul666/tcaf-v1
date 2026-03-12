import os
from docx import Document
from reporting.base_report import BaseReport


class Clause192Report(BaseReport):
    """ITSAR Clause 1.9.2 — Port Scanning Compliance Report."""

    CLAUSE_ID = "1.9.2"

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
        table.rows[1].cells[1].text = "1.9.2"
        table.rows[2].cells[0].text = "Requirement"
        table.rows[2].cells[1].text = "Open Port Compliance"

        self.add_data_cell_padding(table)
        self.prevent_table_row_split(table)
        doc.add_paragraph()

        # ── 3. Requirement Description ──
        self.add_itsar_heading(doc, "3. Requirement Description", 2)
        doc.add_paragraph(
            "It shall be ensured that on all network interfaces, only vendor documented/"
            "identified ports on the transport layer respond to requests from outside the system. "
            "List of the identified open ports shall match the list of network services that are "
            "necessary for the operation of the CPE."
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
        doc.add_paragraph(
            "\u2022 The tester system has nmap, tcpdump, tshark, and Wireshark installed."
        )
        doc.add_paragraph(
            "\u2022 The tester has sufficient privileges to run SYN, UDP, and SCTP scans."
        )
        doc.add_paragraph()

        # ── 5. Test Objective ──
        self.add_itsar_heading(doc, "5. Test Objective", 2)
        doc.add_paragraph(
            "To identify all open ports on the DUT using TCP SYN, UDP, and SCTP INIT "
            "scan techniques. The discovered open ports are documented with packet "
            "capture evidence showing the request and response for each open port."
        )
        doc.add_paragraph()

        # ── 6. Test Scenario ──
        self.add_itsar_heading(doc, "6. Test Scenario", 2)

        self.add_itsar_subheading(doc, "6.1 Tools Required", 2)
        doc.add_paragraph("\u2022 nmap (port scanning)")
        doc.add_paragraph("\u2022 tcpdump (packet capture)")
        doc.add_paragraph("\u2022 tshark (packet analysis)")
        doc.add_paragraph("\u2022 Wireshark (visual evidence)")
        doc.add_paragraph("\u2022 Linux-based tester system")

        self.add_itsar_subheading(doc, "6.2 Test Execution Steps", 2)
        doc.add_paragraph(
            "\u2022 Start packet capture on the tester interface using tcpdump."
        )
        doc.add_paragraph(
            "\u2022 Run nmap scan against the DUT for all 65535 ports."
        )
        doc.add_paragraph(
            "\u2022 Stop the packet capture after the scan completes."
        )
        doc.add_paragraph(
            "\u2022 Parse nmap output to identify open ports."
        )
        doc.add_paragraph(
            "\u2022 Take Wireshark screenshots for each discovered open port showing "
            "the request and response packets."
        )
        doc.add_paragraph()

        # ── 7. Expected Results ──
        self.add_itsar_heading(doc, "7. Expected Results", 2)
        doc.add_paragraph(
            "Only documented and necessary service ports should be found open. "
            "The packet captures should show the SYN/SYN-ACK handshake (TCP), "
            "response packets (UDP), or INIT/INIT-ACK (SCTP) for each open port."
        )
        doc.add_paragraph()

        # ── 8. Test Execution ──
        self.add_itsar_heading(doc, "8. Test Execution", 2)

        scan_types = {
            "TC1_TCP_SCAN": ("TCP SYN Scan", "nmap -sS -p- -Pn -n -T4"),
            "TC2_UDP_SCAN": ("UDP Scan", "nmap -sU -p- -Pn -n -T4"),
            "TC3_SCTP_SCAN": ("SCTP INIT Scan", "nmap -sY -p- -Pn -n -T4"),
        }

        for idx, tc in enumerate(results, start=1):
            scan_info = scan_types.get(tc.name, (tc.name, "nmap"))
            scan_label, scan_cmd = scan_info

            h = self.add_itsar_subheading(doc, f"8.{idx} Test Case: {tc.name}", 2)
            self.keep_with_next(h)

            doc.add_paragraph(f"Description: {tc.description}")

            self.add_bold_paragraph(doc, "Scan Type:")
            doc.add_paragraph(scan_label)

            self.add_bold_paragraph(doc, "Execution Command:")
            doc.add_paragraph(f"{scan_cmd} {getattr(context, 'dut_ip', 'N/A')}")

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
                f"The following scan(s) did not complete successfully: {names}. "
                "Review the evidence to determine if unexpected ports are open "
                "on the DUT."
            )
        else:
            doc.add_paragraph(
                "All port scanning test cases completed successfully. "
                "The open ports discovered on the DUT have been documented "
                "with packet capture evidence for compliance review."
            )
        doc.add_paragraph()

        # ── 10. Test Case Result Summary ──
        self.add_result_summary(doc, results, section_num="10")

        # Save
        report_path = self.get_report_path(self.CLAUSE_ID)
        doc.save(report_path)
        return report_path
