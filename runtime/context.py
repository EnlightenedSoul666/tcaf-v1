import uuid
from datetime import datetime
from evidence.manager import EvidenceManager


class RuntimeContext:
    """
    Shared runtime state used across the ITSAR compliance framework.
    """

    def __init__(self, clause=None, section=None, ssh_user=None, dut_ip=None, ssh_password=None, dut_ipv6=None,
                 snmp_user=None, snmp_auth_pass=None, snmp_priv_pass=None,
                 sudo_password=None, openwrt_ip=None, openwrt_ipv6=None, openwrt_password=None,
                 metasploitable_ip=None, metasploitable_ipv6=None,
                 metasploitable_user=None, metasploitable_password=None,
                 nonsense_ip=None, nonsense_ipv6=None):

        self.execution_id = str(uuid.uuid4())

        self.start_time = datetime.utcnow()

        # CLI parameters
        self.clause = clause
        self.section = section
        self.ssh_user = ssh_user
        self.dut_ip = dut_ip
        self.dut_ipv6 = dut_ipv6
        self.ssh_password = ssh_password
        self.snmp_user = snmp_user
        self.snmp_auth_pass = snmp_auth_pass
        self.snmp_priv_pass = snmp_priv_pass

        # Sudo and OpenWRT credentials
        self.sudo_password = sudo_password
        self.openwrt_ip = openwrt_ip
        self.openwrt_ipv6 = openwrt_ipv6
        self.openwrt_password = openwrt_password

        # ICMP-specific: Metasploitable and nonsense IPs
        self.metasploitable_ip = metasploitable_ip
        self.metasploitable_ipv6 = metasploitable_ipv6
        self.metasploitable_user = metasploitable_user
        self.metasploitable_password = metasploitable_password
        self.nonsense_ip = nonsense_ip
        self.nonsense_ipv6 = nonsense_ipv6

        # Core subsystems (initialized later)
        self.ssh_connection = None
        self.terminal_manager = None

        # Device information
        self.device_type = None
        self.device_info = {}

        # Adapter
        self.adapter = None

        # Evidence tracking
        self.evidence = EvidenceManager()

        self.current_testcase = None

        self.pcap_process = None
        self.pcap_file = None

        # Tester's network interface (auto-resolved in prepare_context()
        # via `ip route get <dut_ip>` -> "dev <iface>"). Falls back to eth0
        # if resolution fails.
        self.tester_iface = None

        self.browser = None

        self.dut_model = "Metasploitable 2"
        self.dut_serial = "332373013881"
        self.dut_firmware = "7.0.0.0.6365"

        self.dut_name = None
        self.dut_version = None
        self.os_hash = None
        self.config_hash = None

        self.itsar_section = "1.1 Access and Authorization"
        self.itsar_requirement = "1.1.1 Management Protocols Entity Mutual Authentication"

    def summary(self):
        """
        Return basic execution summary.
        """

        return {
            "execution_id": self.execution_id,
            "clause": self.clause,
            "section": self.section,
            "device_type": self.device_type,
            "start_time": str(self.start_time),
        }
