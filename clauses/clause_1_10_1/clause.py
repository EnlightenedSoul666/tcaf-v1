from clauses.clause_1_10_1.tc1_icmp import TC1ICMPIPv4
from clauses.clause_1_10_1.tc2_icmp import TC2ICMPIPv6


class Clause_1_10_1:
    def __init__(self, context):
        self.id = "1.10.1"
        # 1. We save the context to the class here!
        self.context = context 

    def run(self):
        # 2. We use 'self.context' everywhere inside this function
        self.context.clause = self.id
        results = []
        
        # Run TC1: IPv4 ICMP Tests
        tc1 = TC1ICMPIPv4()
        results.append(tc1.run(self.context))
        
        # Run TC2: IPv6 ICMP Tests
        tc2 = TC2ICMPIPv6()
        results.append(tc2.run(self.context))
        
        return results