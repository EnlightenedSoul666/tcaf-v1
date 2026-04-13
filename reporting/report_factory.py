"""
Report Factory — creates the appropriate report generator for a clause.

Supports two formats:
  - "docx" (default) — python-docx based DOCX reports
  - "pdf"  — ReportLab native PDF reports (blue professional theme)
"""

# ── DOCX Reports ──────────────────────────────────────────────────────────
from reporting.clause_reports.clause_1_1_1_report import Clause111Report
from reporting.clause_reports.clause_1_9_2_report import Clause192Report
from reporting.clause_reports.clause_1_10_2_report import Clause1102Report

# ── PDF Reports (ReportLab) ──────────────────────────────────────────────
from reporting.pdf_reports.pdf_clause_1_1_1 import PDFClause111Report
from reporting.pdf_reports.pdf_clause_1_9_2 import PDFClause192Report
from reporting.pdf_reports.pdf_clause_1_10_2 import PDFClause1102Report


DOCX_REGISTRY = {
    "1.1.1":  Clause111Report,
    "1.9.2":  Clause192Report,
    "1.10.2": Clause1102Report,
}

PDF_REGISTRY = {
    "1.1.1":  PDFClause111Report,
    "1.9.2":  PDFClause192Report,
    "1.10.2": PDFClause1102Report,
}


class ReportFactory:

    @staticmethod
    def create(context, results, fmt="docx"):
        """
        Create a report generator instance.

        Args:
            context:  RuntimeContext object
            results:  list of TestCase result objects
            fmt:      "docx" or "pdf"

        Returns:
            Report instance with a .generate(context, results) method
        """
        clause = context.clause

        if fmt == "pdf":
            registry = PDF_REGISTRY
        else:
            registry = DOCX_REGISTRY

        report_cls = registry.get(clause)
        if report_cls is None:
            raise Exception(
                f"No {fmt.upper()} report template for clause {clause}. "
                f"Available: {list(registry.keys())}"
            )

        return report_cls(context, results)
