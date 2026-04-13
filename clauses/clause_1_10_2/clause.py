import subprocess
from core.clause import BaseClause
from clauses.clause_1_10_2.tc1_icmp import TC1ICMPIPv4
from clauses.clause_1_10_2.tc2_icmp import TC2ICMPIPv6


def _discover_ipv6_via_ssh(host, username, password):
    """SSH into a machine and return its first global-scope ULA IPv6 address."""
    cmd = (
        f"sshpass -p '{password}' ssh -o KexAlgorithms=diffie-hellman-group-exchange-sha1 "
        f"-o HostKeyAlgorithms=ssh-rsa -o Ciphers=aes256-cbc "
        f"-o StrictHostKeyChecking=no -o ConnectTimeout=5 "
        f"{username}@{host} 'ip -6 addr show scope global 2>/dev/null; ifconfig 2>/dev/null'"
    )
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        addresses = []
        for line in result.stdout.splitlines():
            line = line.strip()
            # Modern 'ip' format: "inet6 fdd4:48ab:15e6::1/60 scope global ..."
            if line.startswith("inet6 ") and "scope global" in line.lower():
                addr = line.split()[1].split("/")[0]
                addresses.append(addr)
            # Old ifconfig format: "inet6 addr: fdd4:.../64 Scope:Global"
            elif "inet6 addr:" in line and "scope:global" in line.lower():
                part = line.split("inet6 addr:")[1].strip().split("/")[0].strip()
                addresses.append(part)

        # Prefer ULA addresses (fd/fc prefix) — matches typical lab networks
        for addr in addresses:
            if addr.startswith("fd") or addr.startswith("fc"):
                return addr
        return addresses[0] if addresses else None
    except Exception as e:
        print(f"    [!] SSH to {host} failed: {e}")
        return None


class Clause_1_10_2(BaseClause):

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
        1. Ensure DuT = OpenWRT (same IP)
        2. Map auxiliary machine IPs (Metasploitable) onto generic attributes
        3. Auto-discover IPv6 addresses via SSH (before PCAP starts)
        4. Strip any IPv6 prefix lengths
        """
        # ── DuT = OpenWRT ────────────────────────────────────────────────────
        if self.context.openwrt_ip:
            self.context.dut_ip = self.context.openwrt_ip

        # Override the global default (Metasploitable 2) so the DUT Details
        # table in the report correctly identifies OpenWRT as the DuT.
        self.context.dut_model    = "OpenWRT Router"
        self.context.dut_serial   = "N/A"
        self.context.dut_firmware = getattr(
            self.context, "openwrt_firmware", "OpenWRT (auto-detected)"
        )

        self.context.auxiliary_ip = getattr(self.context, "metasploitable_ip", None)

        # ── Auto-discover IPv6 addresses via SSH ─────────────────────────────
        # This runs BEFORE any PCAP capture, so SSH packets won't contaminate
        print("\n[*] Auto-discovering IPv6 addresses via SSH...")

        # OpenWRT → becomes DuT IPv6
        if self.context.openwrt_ip and self.context.openwrt_password:
            ipv6 = _discover_ipv6_via_ssh(
                self.context.openwrt_ip, "root", self.context.openwrt_password)
            if ipv6:
                self.context.openwrt_ipv6 = ipv6
                self.context.dut_ipv6 = ipv6   # DuT IS OpenWRT
                print(f"    OpenWRT / DuT ({self.context.openwrt_ip}):  {ipv6}")
            else:
                print(f"    OpenWRT / DuT ({self.context.openwrt_ip}):  [not found]")

        # Metasploitable → becomes auxiliary IPv6
        meta_ip = getattr(self.context, "metasploitable_ip", None)
        meta_user = getattr(self.context, "metasploitable_user", None)
        meta_pass = getattr(self.context, "metasploitable_password", None)
        if meta_ip and meta_user and meta_pass:
            ipv6 = _discover_ipv6_via_ssh(meta_ip, meta_user, meta_pass)
            if ipv6:
                self.context.auxiliary_ipv6 = ipv6
                print(f"    Metasploitable ({meta_ip}):  {ipv6}")
            else:
                print(f"    Metasploitable ({meta_ip}):  [not found]")

        # If auxiliary_ipv6 wasn't auto-discovered, fall back to manual value
        if not getattr(self.context, "auxiliary_ipv6", None):
            self.context.auxiliary_ipv6 = getattr(self.context, "metasploitable_ipv6", None)

        # ── Strip prefix lengths from all IPv6 addresses ─────────────────────
        for attr in ("dut_ipv6", "openwrt_ipv6", "auxiliary_ipv6", "nonsense_ipv6"):
            val = getattr(self.context, attr, None)
            if val and "/" in val:
                setattr(self.context, attr, val.split("/")[0])

        print("[*] Context ready.\n")
