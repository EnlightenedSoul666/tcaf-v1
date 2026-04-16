"""
Clause 1.10.2 — ICMP handling compliance.

IPv6 address discovery uses ARP+NDP (no SSH). The tester resolves its own
outbound interface from the kernel routing table, ARPs the DuT / auxiliary
machine to learn their MACs, seeds the IPv6 neighbour cache with an
all-nodes multicast ping, then matches MAC -> IPv6 in `ip -6 neigh show`.

This avoids SSH key-exchange/cipher negotiation pain and keeps the PCAP
free of SSH traffic that would otherwise contaminate the capture window.
"""
import re
import secrets
import subprocess

from core.clause import BaseClause
from clauses.clause_1_10_2.tc1_icmp import TC1ICMPIPv4
from clauses.clause_1_10_2.tc2_icmp import TC2ICMPIPv6


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def _sh(cmd, timeout=8):
    """Run a shell command, return stdout on success or '' on any failure."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Interface resolution
# ---------------------------------------------------------------------------

def _resolve_tester_iface(ipv4):
    """
    Ask the kernel which interface would be used to reach `ipv4`.
    `ip route get <ip>` output contains '... dev <iface> ...'.
    """
    if not ipv4:
        return None
    out = _sh(f"ip route get {ipv4}")
    m = re.search(r"\bdev\s+(\S+)", out)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# ARP + NDP discovery
# ---------------------------------------------------------------------------

def _mac_from_ipv4(ipv4, iface):
    """Seed ARP cache via ping, then read MAC from `ip neigh show`."""
    _sh(f"ping -c 1 -W 1 -I {iface} {ipv4}")
    out = _sh(f"ip neigh show {ipv4} dev {iface}")
    m = re.search(r"lladdr\s+([0-9a-f:]{17})", out)
    return m.group(1).lower() if m else None


def _discover_ipv6_via_ndp(ipv4, iface):
    """
    Resolve IPv6 from IPv4 using ARP -> NDP.

      1. ARP the IPv4 neighbour to get its MAC.
      2. Ping ff02::1 (all-nodes multicast) to populate the IPv6 neighbour cache.
      3. Scan `ip -6 neigh show` for rows whose lladdr matches the MAC.
      4. Prefer ULA (fd/fc) > GUA (2xxx/3xxx) > link-local (fe80::, zoned).
    """
    if not (ipv4 and iface):
        return None

    mac = _mac_from_ipv4(ipv4, iface)
    if not mac:
        return None

    # Seed IPv6 neighbour cache. Short timeout; we don't care about replies,
    # only that the kernel learns the mappings.
    _sh(f"ping6 -c 2 -W 1 -I {iface} ff02::1", timeout=5)

    out = _sh(f"ip -6 neigh show dev {iface}")
    candidates = []
    for line in out.splitlines():
        m = re.match(r"(\S+)\s+lladdr\s+([0-9a-f:]{17})", line)
        if m and m.group(2).lower() == mac:
            candidates.append(m.group(1))

    # ULA first (matches typical lab networks using fd.../fc... prefixes).
    for pref in ("fd", "fc"):
        for a in candidates:
            if a.lower().startswith(pref):
                return a
    # Then global unicast.
    for a in candidates:
        if a and a[0] in "23":
            return a
    # Last resort: link-local with zone id so ping6 / scapy can use it.
    for a in candidates:
        if a.lower().startswith("fe80"):
            return f"{a}%{iface}"

    return None


# ---------------------------------------------------------------------------
# Nonsense IPv6 generation
# ---------------------------------------------------------------------------

_RESERVED_IPV6_PREFIXES = ("0:", "::", "ff", "fe8", "fe9", "fea", "feb")


def _is_reserved_or_empty_ipv6(addr):
    """
    Reject IPv6 nonsense-targets that will be dropped by the tester kernel
    or by OpenWRT's bogon filter before they can provoke an ICMP error.

    Covers:
      - None / empty
      - The 0000::/8 reserved range (e.g. '5::5')
      - Multicast (ff00::/8) -- routers don't send Dest Unreachable for these
      - Link-local (fe80::/10) -- stays on-link, never triggers forwarding
    """
    if not addr:
        return True
    s = addr.strip().lower()
    if not s:
        return True
    return s.startswith(_RESERVED_IPV6_PREFIXES)


def _random_ula_nonsense(openwrt_ipv6):
    """
    Build an unused address inside the same /64 ULA prefix as the DuT.

    If openwrt_ipv6 = 'fdd4:48ab:15e6::1', we take the first three hextets
    ('fdd4:48ab:15e6') as the /64 prefix and append a random 64-bit host id.
    OpenWRT then tries to forward to an address on its own LAN prefix that
    has no neighbour -> clean ICMPv6 'address unreachable' (Type 1, code 3).
    """
    if not openwrt_ipv6:
        return None

    base = openwrt_ipv6.split("%")[0]  # strip any '%iface' zone id
    # Normalise '::' and take first three hextets as the /64 prefix.
    # Examples handled:
    #   'fdd4:48ab:15e6::1'             -> 'fdd4:48ab:15e6'
    #   'fdd4:48ab:15e6:0:xxxx:yyyy::1' -> 'fdd4:48ab:15e6:0'
    left = base.split("::", 1)[0]
    hextets = left.split(":")
    if len(hextets) < 3:
        return None
    prefix = ":".join(hextets[:3])

    # 64-bit random interface id, formatted as four hextets.
    rand = secrets.token_bytes(8)
    host = ":".join(f"{int.from_bytes(rand[i:i+2], 'big'):x}" for i in (0, 2, 4, 6))
    return f"{prefix}:{host}"


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
        1. Resolve the tester's outbound interface from the kernel.
        2. DuT = OpenWRT (same IP).
        3. Map Metasploitable IPs onto generic auxiliary_* attributes.
        4. Auto-discover IPv6 addresses via ARP+NDP (no SSH, no PCAP noise).
        5. Fill in a random ULA nonsense_ipv6 if the user didn't supply a
           usable one (5::5 and similar reserved junk rejected).
        6. Strip any IPv6 prefix lengths.
        """
        ctx = self.context

        # ── 1. Tester interface ──────────────────────────────────────────────
        iface = _resolve_tester_iface(ctx.openwrt_ip or ctx.dut_ip)
        if iface:
            ctx.tester_iface = iface
            print(f"[*] Tester interface resolved: {iface}")
        else:
            ctx.tester_iface = "eth0"
            print("[!] Could not resolve tester interface from routing table; "
                  "falling back to eth0.")

        # ── 2. DuT = OpenWRT ─────────────────────────────────────────────────
        if ctx.openwrt_ip:
            ctx.dut_ip = ctx.openwrt_ip

        # Override the global Metasploitable 2 defaults so the DUT Details
        # table in the report correctly identifies OpenWRT as the DuT.
        ctx.dut_model    = "OpenWRT Router"
        ctx.dut_serial   = "N/A"
        ctx.dut_firmware = getattr(
            ctx, "openwrt_firmware", "OpenWRT (auto-detected)"
        )

        ctx.auxiliary_ip = getattr(ctx, "metasploitable_ip", None)

        # ── 3. Auto-discover IPv6 via ARP+NDP (no SSH) ───────────────────────
        print("\n[*] Auto-discovering IPv6 addresses via ARP+NDP...")

        # OpenWRT / DuT
        if ctx.openwrt_ip:
            ipv6 = _discover_ipv6_via_ndp(ctx.openwrt_ip, ctx.tester_iface)
            if ipv6:
                ctx.openwrt_ipv6 = ipv6
                ctx.dut_ipv6 = ipv6
                print(f"    OpenWRT / DuT ({ctx.openwrt_ip}):  {ipv6}")
            else:
                print(f"    OpenWRT / DuT ({ctx.openwrt_ip}):  [not found via NDP]")

        # Metasploitable / auxiliary
        meta_ip = getattr(ctx, "metasploitable_ip", None)
        if meta_ip:
            ipv6 = _discover_ipv6_via_ndp(meta_ip, ctx.tester_iface)
            if ipv6:
                ctx.auxiliary_ipv6 = ipv6
                print(f"    Metasploitable ({meta_ip}):  {ipv6}")
            else:
                print(f"    Metasploitable ({meta_ip}):  [not found via NDP]")

        # Fall back to manually-supplied metasploitable_ipv6 if NDP failed.
        if not getattr(ctx, "auxiliary_ipv6", None):
            ctx.auxiliary_ipv6 = getattr(ctx, "metasploitable_ipv6", None)

        # ── 4. Nonsense IPv6: reject reserved junk, generate random ULA ─────
        if _is_reserved_or_empty_ipv6(getattr(ctx, "nonsense_ipv6", None)):
            original = getattr(ctx, "nonsense_ipv6", None)
            generated = _random_ula_nonsense(ctx.openwrt_ipv6)
            if generated:
                ctx.nonsense_ipv6 = generated
                if original:
                    print(f"[!] Supplied nonsense_ipv6 '{original}' is reserved/"
                          f"invalid; replaced with random ULA {generated}")
                else:
                    print(f"[*] Generated random ULA nonsense_ipv6: {generated}")

        # ── 5. Strip /NN suffixes from every IPv6 we ended up with ───────────
        for attr in ("dut_ipv6", "openwrt_ipv6", "auxiliary_ipv6", "nonsense_ipv6"):
            val = getattr(ctx, attr, None)
            if val and "/" in val:
                setattr(ctx, attr, val.split("/")[0])

        print("[*] Context ready.\n")
