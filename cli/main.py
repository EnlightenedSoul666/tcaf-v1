import typer
import getpass
from config.settings import initialize_directories
from utils.logger import logger
from core.engine import Engine
from clauses.registry import CLAUSE_REGISTRY


app = typer.Typer(
    help="ICAF - Indian Compliance Authority Framework"
)

@app.command()
def run(
    clause: str = typer.Option(None, "--clause", help="Run a specific clause"),
    section: str = typer.Option(None, "--section", help="Run a section of clauses"),
):
    initialize_directories()

    logger.info("ICAF CLI started")

    # Look up what this clause needs from its class declaration
    clause_class = CLAUSE_REGISTRY.get(clause)
    has_auxiliary = clause_class and getattr(clause_class, "REQUIRES_AUXILIARY", False)

    # ==================================================================
    # DuT / OpenWRT IP
    # For auxiliary clauses (ICMP): DuT IS the OpenWRT router — ask once
    # For other clauses: ask for DuT IP only
    # ==================================================================
    openwrt_ip = None
    openwrt_ipv6 = None
    openwrt_password = None

    if has_auxiliary:
        # DuT = OpenWRT router (single prompt, no separate DuT/OpenWRT)
        openwrt_ip = input("Enter DuT (OpenWRT Router) IP address: ")
        dut_ip = openwrt_ip  # they are the same
        openwrt_password = getpass.getpass("Enter OpenWRT root password: ")
    else:
        dut_ip = input("Enter DuT IP address: ")

    # ==================================================================
    # IPv6 — skip for auxiliary clauses (auto-discovered via SSH)
    # ==================================================================
    dut_ipv6 = None
    if clause_class and clause_class.REQUIRES_IPV6 and not has_auxiliary:
        dut_ipv6 = input("Enter DuT IPv6 address: ")

    # ==================================================================
    # SSH credentials (for SSH-based clauses like 1.1.1)
    # ==================================================================
    ssh_user = None
    ssh_password = None
    if clause_class and clause_class.REQUIRES_SSH:
        ssh_user = input("Enter SSH username: ")
        ssh_password = getpass.getpass("Enter SSH password: ")

    # ==================================================================
    # Sudo password (for Kali)
    # ==================================================================
    sudo_password = None
    if clause_class and clause_class.REQUIRES_SUDO:
        sudo_password = getpass.getpass("Enter sudo password (for Kali): ")

    # ==================================================================
    # OpenWRT — for non-auxiliary clauses that need it
    # ==================================================================
    if clause_class and clause_class.REQUIRES_OPENWRT and not has_auxiliary:
        openwrt_ip = input("Enter OpenWRT (DuT router) IP address: ")
        openwrt_ipv6 = input("Enter OpenWRT (DuT router) IPv6 address: ")
        openwrt_password = getpass.getpass("Enter OpenWRT root password: ")

    # ==================================================================
    # Auxiliary machine (Metasploitable — for ICMP Redirect tests)
    #
    # IPv6 addresses are auto-discovered via ARP+NDP in the clause's
    # prepare_context(). The OpenWRT and Metasploitable IPv6 prompts are
    # OPTIONAL — leave them blank to auto-discover, or enter the ULA
    # directly if NDP can't find it (e.g. Metasploitable has SLAAC
    # disabled, or your tester doesn't have a ULA). Manual values win.
    # The nonsense IPv6 is also auto-generated from the DuT's ULA prefix
    # if the user doesn't supply a usable one.
    # ==================================================================
    metasploitable_ip = None
    metasploitable_ipv6 = None
    metasploitable_user = None
    metasploitable_password = None
    nonsense_ip = None
    nonsense_ipv6 = None
    if has_auxiliary:
        metasploitable_ip = input("Enter auxiliary machine (Metasploitable) IPv4 address: ")
        openwrt_ipv6 = input(
            "Enter OpenWRT IPv6 ULA [blank = auto-discover via NDP]: "
        ).strip() or None
        metasploitable_ipv6 = input(
            "Enter Metasploitable IPv6 ULA [blank = auto-discover via NDP]: "
        ).strip() or None
        nonsense_ip = input("Enter nonsense IPv4 address (unreachable): ")
        nonsense_ipv6 = input(
            "Enter nonsense IPv6 address [blank = auto-generate in DuT's ULA]: "
        ).strip() or None
        print("  (Any blank IPv6 address will be auto-discovered/generated)")

    engine = Engine(
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

    engine.start()

def main():
    app()


if __name__ == "__main__":
    main()
