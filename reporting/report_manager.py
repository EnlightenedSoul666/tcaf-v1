"""
Report Manager — orchestrates report generation.

Generates both DOCX and PDF reports by default. Can be configured
to generate only one format via the `formats` parameter.
"""

from reporting.report_factory import ReportFactory
from utils.logger import logger


class ReportManager:

    def generate(self, context, results, formats=None):
        """
        Generate compliance reports.

        Args:
            context:  RuntimeContext object
            results:  list of TestCase result objects
            formats:  list of formats to generate, e.g. ["docx", "pdf"]
                      defaults to ["docx", "pdf"] (both)

        Returns:
            dict mapping format -> output file path
              e.g. {"docx": "/path/to/report.docx", "pdf": "/path/to/report.pdf"}
        """
        if formats is None:
            formats = ["docx", "pdf"]

        paths = {}

        for fmt in formats:
            try:
                logger.info(f"Generating {fmt.upper()} compliance report for clause {context.clause}")
                report = ReportFactory.create(context, results, fmt=fmt)
                path = report.generate(context, results)
                paths[fmt] = path
                logger.info(f"{fmt.upper()} report generated: {path}")
            except Exception as e:
                logger.error(f"Failed to generate {fmt.upper()} report: {e}")
                paths[fmt] = None

        return paths
