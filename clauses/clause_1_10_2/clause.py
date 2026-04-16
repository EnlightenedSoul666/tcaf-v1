"""
Clause 1.10.2 — ICMP handling compliance.

IPv6 address discovery uses ARP+NDP (no SSH). The tester resolves its own
outbound interface from the kernel routing table, ARPs the DuT / auxiliary
machine to learn their MACs, seeds the IPv6 neighbour cache with an
all-nodes multicast ping, then matches MAC -> IPv6 in `ip -6 neigh show`.

This avoids SSH key-exchange/cipher negotiation pain and keeps the PCAP
free of SSH traffic that would otherwise contaminate the capture window.
"""
import ipaddress
import re
import secrets
import subprocess

from core.clause import BaseClause
from clauses.clause_1_10_2.tc1_icmp import TC1ICMPIPv4
from clauses.clause_1_10_2.tc2_icmp import TC2ICMPIPv6


def _valid_ipv6(addr):
    """Return normalised string form if `addr` parses as a valid IPv6, else None."""
    if not addr:
        return None
    try:
        return str(ipaddress.IPv6Address(addr.split("%")[0]))
    except (ipaddress.AddressValueError, ValueError):
        return None


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


def _first_four_hextets(ipv6):
    """Return the /64 prefix of an IPv6 address as 'aaaa:bbbb:cccc:dddd'."""
    if not ipv6:
        return None
    addr = ipv6.split("%")[0].split("/")[0]
    if "::" in addr:
        left, right = addr.split("::", 1)
        lparts = [p for p in left.split(":") if p]
        rparts = [p for p in right.split(":") if p]
        missing = 8 - len(lparts) - len(rparts)
        parts = lparts + ["0"] * missing + rparts
    else:
        parts = addr.split(":")
    if len(parts) < 4:
        return None
    return ":".join(parts[:4])


def _mac_to_eui64(mac):
    """aa:bb:cc:dd:ee:ff -> a8bb:ccff:fedd:eeff (SLAAC EUI-64 with U/L bit flipped)."""
    try:
        b = [int(p, 16) for p in mac.split(":")]
        if len(b) != 6:
            return None
        b[0] ^= 0x02  # flip Universal/Local bit
        return (
            f"{b[0]:02x}{b[1]:02x}:{b[2]:02x}ff:"
            f"fe{b[3]:02x}:{b[4]:02x}{b[5]:02x}"
        )
    except (ValueError, IndexError):
        return None


def _tester_ula_prefix(iface):
    """
    Extract a /64 ULA prefix from one of the tester's OWN addresses on this
    interface. The tester will have been SLAAC-configured from OpenWRT's RA,
    so it holds a ULA in the same prefix as OpenWRT and Metasploitable.
    """
    out = _sh(f"ip -6 addr show dev {iface}")
    for line in out.splitlines():
        m = re.search(r"inet6\s+([0-9a-fA-F:]+)/\d+\s+scope\s+global", line)
        if m:
            addr = m.group(1)
            if addr.lower().startswith(("fd", "fc")):
                return _first_four_hextets(addr)
    return None


def _default_ipv6_via(iface):
    """
    Return the 'via' address of the IPv6 default route on `iface`.
    This IS OpenWRT's address (ULA preferred, then GUA, then link-local).
    """
    out = _sh("ip -6 route show")
    ula = gua = lla = None
    for line in out.splitlines():
        m = re.search(
            r"default\s+via\s+([0-9a-fA-F:]+).*\bdev\s+" + re.escape(iface),
            line,
        )
        if m:
            addr = m.group(1).lower()
            if addr.startswith(("fd", "fc")) and ula is None:
                ula = addr
            elif addr[0] in "23" and gua is None:
                gua = addr
            elif addr.startswith("fe80") and lla is None:
                lla = f"{addr}%{iface}"
    return ula or gua or lla


def _ping6_reachable(addr, iface, timeout=2):
    """Return True if one ICMPv6 echo reply comes back."""
    out = _sh(
        f"ping6 -c 1 -W {timeout} -I {iface} {addr}",
        timeout=timeout + 2,
    )
    return "bytes from" in out or "icmp_seq=" in out


def _discover_ipv6_via_ndp(ipv4, iface, is_dut=False):
    """
    Resolve a neighbour's GLOBAL-SCOPE IPv6 address from its IPv4 address.

    We explicitly avoid returning link-local (fe80::) addresses when a ULA
    or GUA is reachable, because:
      - Scapy / tshark display filters don't handle `%iface` zone ids well.
      - `ip -6 route add ... via fe80::...` needs the zone id too, and
        readability + reliability drop dramatically.

    Strategy (first hit wins):
      1. ARP the IPv4 to learn the MAC.
      2. If DuT: read `ip -6 route show default` -- the `via` IS OpenWRT.
      3. Build a candidate from (tester's ULA prefix) + (target's EUI-64);
         for the DuT also try `prefix::1` (common router convention).
         Ping each candidate; first responder wins.
      4. Scan `ip -6 neigh show` for any ULA/GUA entry matching the MAC.
      5. Last resort: link-local (with %iface zone id).

    `ping6 ff02::1` is intentionally NOT used -- multicast responders
    always reply from their link-local address, so the NDP cache never
    learns ULA entries from that stimulus alone.
    """
    if not (ipv4 and iface):
        return None

    mac = _mac_from_ipv4(ipv4, iface)
    if not mac:
        return None

    # (2) DuT shortcut: default route's `via` address is OpenWRT's own IPv6.
    if is_dut:
        gw = _default_ipv6_via(iface)
        if gw and gw.lower().startswith(("fd", "fc", "2", "3")):
            _sh(f"ping6 -c 1 -W 1 -I {iface} {gw}")  # populate cache
            return gw

    # (3) Construct candidates from prefix + EUI-64 (and router '::1' for DuT).
    #
    # The tester's SLAAC address gives us 4 hextets of prefix
    # (e.g. 'fdd4:48ab:15e6:0'). We combine with:
    #   - '::1' for the DuT (OpenWRT's typical LAN gateway convention).
    #     '{prefix}::1' is valid because '::' expands to 3 zero groups
    #     (4 + 1 = 5 hextets + 3 zeros = 8).
    #   - EUI-64(target_MAC) for the auxiliary, joined with a SINGLE colon.
    #     '{prefix}:{eui}' gives 4 + 4 = 8 hextets, no '::' needed.
    #     Using '::' here would be invalid (0 zero groups is illegal).
    # Every candidate is validated through ipaddress.IPv6Address before
    # we bother pinging it.
    prefix = _tester_ula_prefix(iface)
    if prefix:
        candidates = []
        if is_dut:
            candidates.append(f"{prefix}::1")  # typical OpenWRT LAN gateway
        eui = _mac_to_eui64(mac)
        if eui:
            candidates.append(f"{prefix}:{eui}")  # SLAAC EUI-64 address
        for raw in candidates:
            c = _valid_ipv6(raw)
            if c and _ping6_reachable(c, iface):
                return c

    # (4) NDP cache scan — anything global-scope matching this MAC.
    out = _sh(f"ip -6 neigh show dev {iface}")
    for want in ("fd", "fc", "2", "3"):
        for line in out.splitlines():
            m = re.match(r"(\S+)\s+lladdr\s+([0-9a-f:]{17})", line)
            if (
                m
                and m.group(2).lower() == mac
                and m.group(1).lower().startswith(want)
            ):
                return m.group(1)

    # (5) Last resort: link-local.
    _sh(f"ping6 -c 2 -W 1 -I {iface} ff02::1", timeout=5)
    out = _sh(f"ip -6 neigh show dev {iface}")
    for line in out.splitlines():
        m = re.match(r"(\S+)\s+lladdr\s+([0-9a-f:]{17})", line)
        if (
            m
            and m.group(2).lower() == mac
            and m.group(1).lower().startswith("fe80")
        ):
            print(
                f"    [!] WARNING: only link-local found for {ipv4} "
                f"({m.group(1)}); ULA/GUA discovery failed."
            )
            return f"{m.group(1)}%{iface}"

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

        # ── 3. IPv6 discovery: manual override first, else ARP+NDP ──────────
        #
        # If the operator supplied `openwrt_ipv6` or `metasploitable_ipv6`
        # on the CLI, trust them verbatim and skip NDP discovery for that
        # target. This is the escape hatch for environments where:
        #   - The tester doesn't have a ULA (no RA received / accept_ra=0)
        #   - Metasploitable doesn't use SLAAC EUI-64
        #   - The target responds to ping but at a non-standard address
        # Manual values are validated through ipaddress.IPv6Address; invalid
        # input is discarded (and NDP is attempted as usual).
        print("\n[*] Resolving IPv6 addresses (manual override > ARP+NDP)...")

        # OpenWRT / DuT
        manual = _valid_ipv6(getattr(ctx, "openwrt_ipv6", None))
        if manual:
            ctx.openwrt_ipv6 = manual
            ctx.dut_ipv6 = manual
            print(f"    OpenWRT / DuT  (manual):  {manual}")
        elif ctx.openwrt_ip:
            ipv6 = _discover_ipv6_via_ndp(
                ctx.openwrt_ip, ctx.tester_iface, is_dut=True
            )
            if ipv6:
                ctx.openwrt_ipv6 = ipv6
                ctx.dut_ipv6 = ipv6
                print(f"    OpenWRT / DuT ({ctx.openwrt_ip}):  {ipv6}")
            else:
                print(f"    OpenWRT / DuT ({ctx.openwrt_ip}):  [not found via NDP]")

        # Metasploitable / auxiliary
        manual = _valid_ipv6(getattr(ctx, "metasploitable_ipv6", None))
        if manual:
            ctx.auxiliary_ipv6 = manual
            print(f"    Metasploitable (manual):  {manual}")
        else:
            meta_ip = getattr(ctx, "metasploitable_ip", None)
            if meta_ip:
                ipv6 = _discover_ipv6_via_ndp(
                    meta_ip, ctx.tester_iface, is_dut=False
                )
                if ipv6:
                    ctx.auxiliary_ipv6 = ipv6
                    print(f"    Metasploitable ({meta_ip}):  {ipv6}")
                else:
                    print(f"    Metasploitable ({meta_ip}):  [not found via NDP]")

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
