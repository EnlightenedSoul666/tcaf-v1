import os
from docx import Document
from reporting.base_report import BaseReport, GREEN, RED


class Clause111Report(BaseReport):
    """ITSAR Clause 1.1.1 — CPE Authentication Compliance Report."""

    CLAUSE_ID = "1.1.1"

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
        table.rows[1].cells[1].text = getattr(context, "itsar_section", "1.1.1")
        table.rows[2].cells[0].text = "Requirement"
        table.rows[2].cells[1].text = getattr(context, "itsar_requirement", "CPE Authentication")

        self.add_data_cell_padding(table)
        self.prevent_table_row_split(table)
        doc.add_paragraph()

        # ── 3. Requirement Description ──
        self.add_itsar_heading(doc, "3. Requirement Description", 2)
        doc.add_paragraph(
            "The CPE shall communicate with authenticated management entities only. "
            "The protocols used for the CPE management shall support mutual authentication "
            "mechanisms, preferably with pre-shared key arrangements or by equivalent entity "
            "mutual authentication mechanisms. This shall be verified for all protocols used "
            "for CPE management. (This feature shall be supported on all WAN management interfaces)."
        )
        doc.add_paragraph()

        # ── 4. Test Execution ──
        self.add_itsar_heading(doc, "4. Test Execution", 2)

        for idx, tc in enumerate(results, start=1):
            h = self.add_itsar_subheading(doc, f"4.{idx} Test Case: {tc.name}", 2)
            self.keep_with_next(h)

            doc.add_paragraph(f"Description: {tc.description}")

            # Status with colour
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

        # ── 5. Test Case Result Summary ──
        self.add_result_summary(doc, results, section_num="5")

        # Save
        report_path = self.get_report_path(self.CLAUSE_ID)
        doc.save(report_path)
        return report_path
