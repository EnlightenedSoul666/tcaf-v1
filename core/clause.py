class BaseClause:

    # Subclasses declare what credentials/info they need
    REQUIRES_SSH       = False
    REQUIRES_IPV6      = False
    REQUIRES_OPENWRT   = False
    REQUIRES_SUDO      = False
    REQUIRES_AUXILIARY  = False

    def __init__(self, context):

        self.context = context
        self.testcases = []

    def add_testcase(self, tc):

        self.testcases.append(tc)

    def prepare_context(self):
        """
        Hook for subclasses to extend or transform the runtime context
        with clause-specific attributes before test execution begins.
        Override this in child clauses — default is a no-op.
        """
        pass

    def run(self):

        # Let the clause set up any clause-specific context attributes
        self.prepare_context()

        results = []

        for tc in self.testcases:

            # Set active testcase in runtime context
            self.context.current_testcase = tc

            result = tc.run(self.context)

            results.append(result)

            # Clear after execution (safe practice)
            self.context.current_testcase = None

        return results