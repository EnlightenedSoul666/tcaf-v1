from core.clause import BaseClause
from .tc1_tcp_scan import TC1TCPScan
from .tc2_udp_scan import TC2UDPScan
from .tc3_sctp_scan import TC3SCTPScan


class Clause_1_9_2(BaseClause):

    REQUIRES_SSH  = False
    REQUIRES_IPV6 = False
    REQUIRES_SUDO = True

    def __init__(self, context):
        super().__init__(context)
        self.add_testcase(TC1TCPScan())
        self.add_testcase(TC2UDPScan())
        self.add_testcase(TC3SCTPScan())
