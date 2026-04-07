from utils.logger import logger
from runtime.context import RuntimeContext
from core.clause_runner import ClauseRunner
from terminal.manager import TerminalManager
from reporting.report_manager import ReportManager

class Engine:

    def __init__(self, clause=None, section=None, ssh_user=None, dut_ip=None, ssh_password=None, dut_ipv6=None,
                 sudo_password=None, openwrt_ip=None, openwrt_ipv6=None, openwrt_password=None,
                 metasploitable_ip=None, metasploitable_ipv6=None,
                 metasploitable_user=None, metasploitable_password=None,
                 nonsense_ip=None, nonsense_ipv6=None):

        self.context = RuntimeContext(
            clause=clause,
            section=section,
            ssh_user=ssh_user,
            dut_ip=dut_ip,
            ssh_password=ssh_password,
            dut_ipv6=dut_ipv6,
            sudo_password=sudo_password,
            openwrt_ip=openwrt_ip,
            openwrt_ipv6=openwrt_ipv6,
            openwrt_password=openwrt_password,
            metasploitable_ip=metasploitable_ip,
            metasploitable_ipv6=metasploitable_ipv6,
            metasploitable_user=metasploitable_user,
            metasploitable_password=metasploitable_password,
            nonsense_ip=nonsense_ip,
            nonsense_ipv6=nonsense_ipv6,
        )

        logger.info("Engine initialized")

    def start(self):

        logger.info("Starting compliance engine")
        logger.info(f"Execution ID: {self.context.execution_id}")

        if self.context.clause:
            logger.info(f"Execution mode: Clause {self.context.clause}")

        elif self.context.section:
            logger.info(f"Execution mode: Section {self.context.section}")

        else:
            logger.info("Execution mode: Full evaluation")

        self.initialize_runtime()

        logger.info("Runtime environment ready")

        runner = ClauseRunner(self.context)

        results = runner.run()

        for tc in results:
            logger.info(f"{tc.name} → {tc.status}")

        # Generate both DOCX and PDF reports
        report_manager = ReportManager()
        report_paths = report_manager.generate(self.context, results)

        for fmt, path in report_paths.items():
            if path:
                logger.info(f"{fmt.upper()} report generated: {path}")

    def initialize_runtime(self):

        logger.info("Initializing runtime environment")

        # Initialize terminal manager and create default "tester" terminal
        self.context.terminal_manager = TerminalManager()
        self.context.terminal_manager.create_terminal("tester")

        logger.info("Terminal manager initialized with 'tester' terminal")
