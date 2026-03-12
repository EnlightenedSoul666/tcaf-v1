from reporting.clause_reports.clause_1_1_1_report import Clause111Report
from reporting.clause_reports.clause_1_9_2_report import Clause192Report
from reporting.clause_reports.clause_1_10_1_report import Clause1101Report


class ReportFactory:

    @staticmethod
    def create(context, results):

        clause = context.clause

        if clause == "1.1.1":
            return Clause111Report(context, results)

        if clause == "1.9.2":
            return Clause192Report(context, results)

        if clause == "1.10.1":
            return Clause1101Report(context, results)

        raise Exception(f"No report template for clause {clause}")
