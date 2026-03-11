import os
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from utils.logger import logger

class PDFGenerator:

    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.styles = getSampleStyleSheet()

    def generate(self, context, results):
        # 1. Define the target directory
        target_dir = f"{context.evidence.run_dir}/{context.clause}/reports"
        os.makedirs(target_dir, exist_ok=True)
        # 2. Grab the timestamped prefix from your manager
        date_prefix = context.evidence.date_prefix
        # 3. Combine them into the final path
        report_path = f"{target_dir}/{date_prefix}_tcaf_report.pdf"

        elements = []
        elements.append(
            Paragraph(
                "Telecom Compliance Automation Framework (TCAF)",
                self.styles["Title"]
            )
        )
        elements.append(Spacer(1, 20))

        # Metadata from context
        elements.append(Paragraph(f"Execution ID: {context.execution_id}", self.styles["Normal"]))
        elements.append(Paragraph(f"DUT IP: {context.ssh_ip}", self.styles["Normal"]))
        elements.append(Paragraph(f"Clause: {context.clause}", self.styles["Normal"]))
        elements.append(Spacer(1, 20))

        # Loop through Test Case Results
        for tc in results:
            elements.append(Paragraph(f"Test Case: {tc.name}", self.styles["Heading2"]))
            elements.append(Paragraph(f"Description: {tc.description}", self.styles["Normal"]))
            elements.append(Paragraph(f"Status: {tc.status}", self.styles["Normal"]))
            elements.append(Spacer(1, 10))

            # Add Evidence (Screenshots only)
            for evidence in tc.evidence:
                # Filter: Only add images. Skip .pcapng and .log files.
                if os.path.exists(evidence) and evidence.lower().endswith(('.png', '.jpg', '.jpeg')):
                    try:
                        elements.append(Image(evidence, width=450, height=250))
                        elements.append(Spacer(1, 10))
                    except Exception as e:
                        logger.error(f"Failed to add image {evidence} to PDF: {e}")

            elements.append(Spacer(1, 20))

        # Build the PDF
        logger.info(f"Generating final report at: {report_path}")
        doc = SimpleDocTemplate(report_path, pagesize=A4)
        doc.build(elements)

        return report_path
