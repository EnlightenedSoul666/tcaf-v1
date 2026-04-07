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

    # Always ask for DuT IP (needed by all clauses)
    # For clauses with REQUIRES_AUXILIARY (e.g. 1.10.1), the DuT is OpenWRT
    # and this IP is the Metasploitable/auxiliary target for Respond tests
    if clause_class and getattr(clause_class, "REQUIRES_AUXILIARY", False):
        dut_ip = input("Enter DuT (Metasploitable) IP address: ")
    else:
        dut_ip = input("Enter DuT IP address: ")

    dut_ipv6 = None
    if clause_class and clause_class.REQUIRES_IPV6:
        if getattr(clause_class, "REQUIRES_AUXILIARY", False):
            dut_ipv6 = input("Enter DuT (Metasploitable) IPv6 address: ")
        else:
            dut_ipv6 = input("Enter DuT IPv6 address: ")

    ssh_user = None
    ssh_password = None
    if clause_class and clause_class.REQUIRES_SSH:
        ssh_user = input("Enter SSH username: ")
        ssh_password = getpass.getpass("Enter SSH password: ")

    sudo_password = None
    if clause_class and clause_class.REQUIRES_SUDO:
        sudo_password = getpass.getpass("Enter sudo password (for Kali): ")

    openwrt_ip = None
    openwrt_ipv6 = None
    openwrt_password = None
    if clause_class and clause_class.REQUIRES_OPENWRT:
        openwrt_ip = input("Enter OpenWRT (DuT router) IP address: ")
        openwrt_ipv6 = input("Enter OpenWRT (DuT router) IPv6 address: ")
        openwrt_password = getpass.getpass("Enter OpenWRT root password: ")

    # Auxiliary machine IPs (e.g. Metasploitable for ICMP Process tests)
    metasploitable_ip = None
    metasploitable_ipv6 = None
    nonsense_ip = None
    nonsense_ipv6 = None
    if clause_class and getattr(clause_class, "REQUIRES_AUXILIARY", False):
        metasploitable_ip   = input("Enter auxiliary machine (Metasploitable) IPv4 address: ")
        metasploitable_ipv6 = input("Enter auxiliary machine (Metasploitable) IPv6 address (or press Enter to skip): ") or None
        nonsense_ip   = input("Enter nonsense IPv4 address (unreachable, no service running): ")
        nonsense_ipv6 = input("Enter nonsense IPv6 address (unreachable, no service running): ")

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
        nonsense_ip=nonsense_ip,
        nonsense_ipv6=nonsense_ipv6,
    )

    engine.start()

def main():
    app()


if __name__ == "__main__":
    main()
