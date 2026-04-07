from core.clause import BaseClause
from clauses.clause_1_10_1.tc1_icmp import TC1ICMPIPv4
from clauses.clause_1_10_1.tc2_icmp import TC2ICMPIPv6


class Clause_1_10_1(BaseClause):

    REQUIRES_SSH       = False
    REQUIRES_IPV6      = True
    REQUIRES_OPENWRT   = True
    REQUIRES_SUDO      = True
    REQUIRES_AUXILIARY  = True

    def __init__(self, context):
        super().__init__(context)
        self.add_testcase(TC1ICMPIPv4())
        self.add_testcase(TC2ICMPIPv6())

    def prepare_context(self):
        """
        Map the auxiliary machine IPs (Metasploitable) onto the generic
        auxiliary_ip / auxiliary_ipv6 attributes that icmp_helpers expects.
        """
        self.context.auxiliary_ip = getattr(self.context, "metasploitable_ip", None)
        self.context.auxiliary_ipv6 = getattr(self.context, "metasploitable_ipv6", None)
